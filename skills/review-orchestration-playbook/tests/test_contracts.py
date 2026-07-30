from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import urllib.parse

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_SCOPE_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
RUNTIME = SCRIPTS / "review_runtime"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS / "independent_codex_pr_review"))

from review_supervisor import constants as independent_constants  # noqa: E402
from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_linux,
    claude_refresh_lock,
    claude_stream_contract,
    claude_version_policy,
    cli,
    providers,
    state,
)


EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS = {
    (
        "2.1.211",
        "darwin-arm64",
        "5a728a76198b6eca7f3c7cdbff43bab44b77b48c2108f7a3107d889773382629",
    ),
    (
        "2.1.211",
        "darwin-x64",
        "33049eb14cf4702b992b7eda41ec077fc6e76539f7fd046e6d32538757235da4",
    ),
    (
        "2.1.211",
        "linux-arm64",
        "1fff7e8f947c07b19d10b1fbf714b7e547e9536253b9b58230d8adbc4624f867",
    ),
    (
        "2.1.211",
        "linux-x64",
        "8272c8a474ac9ea1bc35f19b9f7c7e7dc4dc4eb6d5ad3e484b19335ac72446b2",
    ),
    (
        "2.1.211",
        "linux-arm64-musl",
        "ca094a85ea464b2ebec2ecfcc9e2c056573d4ca95ebe12ffae2c7dccb722e17b",
    ),
    (
        "2.1.211",
        "linux-x64-musl",
        "c99bd7934ac841d5be6ee7d3644cb63bccef2cd495c6c1bb982a1b1deac1b466",
    ),
}


CI_FIXTURE_ROOT = SKILL_ROOT / "tests" / "fixtures" / "ci"
COMPATIBILITY_WORKFLOW_FIXTURE = (
    SKILL_ROOT / "tests" / "fixtures" / "compat" / "codex-review-gate.yml"
)
CI_PROFILE_BY_SKILL_LAYOUT = {
    pathlib.Path("skills/review-orchestration-playbook"): "canonical",
    pathlib.Path("personal_codex/skills/review-orchestration-playbook"): "private",
}
REPOSITORY_POLICY_SCOPE_BY_PROFILE = {
    "canonical": pathlib.Path("."),
    "private": pathlib.Path("personal_codex"),
}


def _has_python_shebang(path: pathlib.Path) -> bool:
    with path.open("rb") as handle:
        first_line = handle.readline(256)
    return first_line.startswith(b"#!") and b"python" in first_line.lower()


def _ci_contract_context(skill_root: pathlib.Path) -> tuple[pathlib.Path, str]:
    layouts = sorted(
        CI_PROFILE_BY_SKILL_LAYOUT.items(),
        key=lambda item: len(item[0].parts),
        reverse=True,
    )
    for layout, profile in layouts:
        layout_depth = len(layout.parts)
        if skill_root.parts[-layout_depth:] != layout.parts:
            continue
        repo_root = skill_root.parents[layout_depth - 1]
        if repo_root / layout != skill_root:
            continue
        return repo_root, profile
    raise AssertionError(f"unsupported review skill layout: {skill_root}")


REPO_ROOT, CI_PROFILE = _ci_contract_context(SKILL_ROOT)


def _repository_policy_scope_root(
    repo_root: pathlib.Path,
    profile: str,
) -> pathlib.Path:
    try:
        relative_scope = REPOSITORY_POLICY_SCOPE_BY_PROFILE[profile]
    except KeyError as error:
        raise AssertionError(
            f"unsupported repository policy profile: {profile}"
        ) from error
    return repo_root / relative_scope


def _repository_agents_path(repo_root: pathlib.Path, profile: str) -> pathlib.Path:
    return _repository_policy_scope_root(repo_root, profile) / "AGENTS.md"


def _claude_auth_repository_policy_files(
    repo_root: pathlib.Path,
    profile: str,
) -> dict[str, str]:
    policy_paths: dict[str, pathlib.Path] = {}
    if profile == "canonical":
        policy_paths = {
            "README.md": repo_root / "README.md",
            "project journal": (
                repo_root
                / "docs/project_journal/2026/07/"
                / "2026-07-17-claude-auth-carriers-c17a11.md"
            ),
        }
    elif profile != "private":
        raise AssertionError(f"unsupported repository policy profile: {profile}")
    return {
        name: path.read_text(encoding="utf-8") for name, path in policy_paths.items()
    }


def _current_claude_contract_files() -> dict[str, str]:
    candidates = {
        "SKILL.md": SKILL_ROOT / "SKILL.md",
        "helper-contract.md": SKILL_ROOT / "references/helper-contract.md",
        "claude-runtime-trust.md": SKILL_ROOT / "references/claude-runtime-trust.md",
        "egress-consent.md": SKILL_ROOT / "references/egress-consent.md",
        "pr-readiness.md": SKILL_ROOT / "references/pr-readiness.md",
        "AGENTS.md": _repository_agents_path(REPO_ROOT, CI_PROFILE),
    }
    if CI_PROFILE == "canonical":
        candidates["README.md"] = REPO_ROOT / "README.md"
    return {name: path.read_text(encoding="utf-8") for name, path in candidates.items()}


def _secret_admission_repository_policy_files(
    repo_root: pathlib.Path,
    profile: str,
) -> dict[str, str]:
    policy_paths: dict[str, pathlib.Path] = {}
    if profile == "canonical":
        policy_paths = {
            "AGENTS.md": _repository_agents_path(repo_root, profile),
            "project journal": (
                repo_root
                / "docs/project_journal/2026/07/"
                / "2026-07-17-secret-reduction-gate-7f1703.md"
            ),
        }
    elif profile != "private":
        raise AssertionError(f"unsupported repository policy profile: {profile}")
    return {
        name: path.read_text(encoding="utf-8") for name, path in policy_paths.items()
    }


class RepositoryContractTest(unittest.TestCase):
    def test_change_delivery_resolves_one_version_per_toolchain(self) -> None:
        skill = (
            SKILL_SCOPE_ROOT / "skills/change-delivery-workflow/SKILL.md"
        ).read_text(encoding="utf-8")

        anchors = (
            "每个 runtime/toolchain",
            "采用单版本还是多版本形态",
            "明确要求本地多版本验证",
            "本次改动目标就是跨版本兼容性",
            "才选择多版本形态",
            "否则使用单版本形态",
        )
        cursor = 0
        for anchor in anchors:
            cursor = skill.index(anchor, cursor) + len(anchor)

        single_version_anchors = (
            "只按 authority/instruction/config 是否存在选择最高优先级来源",
            "不预先判断其能否解析或是否兼容",
            "the user 对本地验证版本的 instruction",
            "repo-local policy 对本地验证版本的 instruction",
            "version-selection config 或 pin",
            "兼容性范围本身不算 version-selection pin",
            "可用的 repo 常规 runner 或项目工具默认解析",
            "本机已安装版本 inventory",
            "只有当前 authority/config/runner/inventory 来源完全不存在时才检查下一个来源",
            "选中来源后再解析并验证",
            "选定 instruction 显式委托给一个具名 repo 机制",
            "该机制属于选中来源的解析过程",
            "若选中 installed inventory",
            "canonical version ordering",
            "满足项目约束的最高已安装版本",
            "明确允许 prerelease",
            "才把 prerelease 纳入候选",
            "最终必须得到唯一且与项目约束兼容的版本",
            "若选中来源内部冲突、无法唯一解析或不兼容",
            "停止并报告 blocker，不得静默降级",
            "将所选 version 及其来源固定用于同一轮验证并记录",
        )
        cursor = skill.index("单版本形态下")
        for anchor in single_version_anchors:
            cursor = skill.index(anchor, cursor) + len(anchor)
        self.assertIn(
            "同一 runtime/toolchain 的最低支持版本和 CI matrix 本身不构成本地多版本门禁",
            skill,
        )
        self.assertLess(skill.index("否则使用单版本形态"), skill.index("单版本形态下"))
        self.assertIn("在多版本形态下", skill)
        self.assertLess(skill.index("单版本形态下"), skill.index("在多版本形态下"))
        multi_version_anchors = (
            "只按 authority/instruction/declaration 是否存在选择最高优先级来源",
            "不预先判断其是否能解析为有效集合",
            "the user 或本次任务对本地多版本验证的 instruction",
            "repo-local policy 对本地多版本验证的 instruction",
            "repo 明确声明的 supported-version set",
            "repo 的 CI matrix",
            "只有当前 authority/instruction/declaration 完全不存在时才检查下一个来源",
            "选中来源后再解析并验证",
            "选定 instruction 显式委托给具名 repo 声明",
            "该声明属于选中来源的解析过程",
            "最终集合必须有限、非空、无重复且每个版本都与项目兼容",
            "选定来源后不比较或合并其他较低优先级来源",
            "较低优先级来源的不同集合不构成冲突",
            "来源冲突仅指选中来源及其显式委托的解析过程内部",
            "若选中来源内部冲突、只能得到开放范围或无法确定有限集合",
            "停止并报告 blocker",
            "不得根据本机已安装版本任意扩张集合",
            "记录最终版本集合及其来源",
        )
        cursor = skill.index("在多版本形态下")
        for anchor in multi_version_anchors:
            cursor = skill.index(anchor, cursor) + len(anchor)
        self.assertIn("只有 suite 已证明顺序复用安全时", skill)
        self.assertIn("才可在同一 checkout 串行执行", skill)
        self.assertIn("版本敏感的 checkout 产物、缓存或状态", skill)
        self.assertIn("独立 worktree/cache/state", skill)
        self.assertIn("或在版本间显式清理并重建", skill)
        self.assertIn("无论使用一个还是多个 worktree", skill)
        self.assertIn("为每次运行分配唯一值或命名空间", skill)
        self.assertIn("否则必须跨所有 worktree 串行执行", skill)
        self.assertIn("已证明为当前任务专属且可丢弃", skill)
        self.assertIn("才可在版本间显式 clean/reset", skill)
        self.assertIn("若状态为共享、所有权不清或不可安全丢弃", skill)
        self.assertIn("需要额外权限时请求明确授权", skill)
        self.assertIn("只有 checkout-local 与机器级资源都已证明隔离时才可并发", skill)

    def test_cleanup_only_legacy_0664_lock_migration_is_private_and_ordered(
        self,
    ) -> None:
        contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )

        anchors = (
            "empty owner-owned mode-`0664` `cleanup.lock`",
            "non-group/other-writable owner-owned `.codex-tmp` root",
            "exact-mode-`0700` state directory",
            "exclusive lock is acquired",
            "revalidates both directories and the lock identity/mode",
            "`fchmod(0600)`",
            "`fsync`",
            "exact mode-`0600` validation",
        )
        cursor = 0
        for anchor in anchors:
            cursor = contract.index(anchor, cursor) + len(anchor)
        self.assertIn("Every other group/other-writable", contract)
        self.assertIn("nonempty legacy lock fails closed", contract)

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
            self.assertFalse((SKILL_SCOPE_ROOT / relative).exists(), relative)

    def test_pr_readiness_continues_until_clean_or_a_crisp_blocker(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "until the effective shape and all delivery gates are clean or a crisp blocker remains",
            readiness,
        )
        self.assertIn("Stop after bounded retries", readiness)

    def test_secret_delta_is_admission_only_for_trusted_reviewer_input(
        self,
    ) -> None:
        repository_policy = _secret_admission_repository_policy_files(
            REPO_ROOT,
            CI_PROFILE,
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("including repository secrets", skill)
        self.assertIn("including tracked repository secrets", helper_contract)
        self.assertIn(
            "tracked `.codex`, `.agents`, and environment files are intentionally readable",
            helper_contract,
        )
        self.assertIn(
            "do not redact, rewrite, or suppress reviewer-visible tracked content",
            skill,
        )
        self.assertIn(
            "Secret admission never delays, suppresses, redacts, or gates reviewer launch",
            helper_contract,
        )
        self.assertIn(
            "does not suppress this trusted reviewer",
            readiness,
        )
        if "AGENTS.md" in repository_policy:
            agents = repository_policy["AGENTS.md"]
            self.assertIn("including tracked repository secrets", agents)
            self.assertIn(
                "Secret-delta analysis never blocks a named reviewer launch",
                agents,
            )
        if "project journal" in repository_policy:
            journal = repository_policy["project journal"]
            self.assertIn("including repository secrets", journal)
            self.assertIn(
                "including tracked `.env`, `.agents`, and `.codex` paths",
                journal,
            )
            self.assertIn(
                "must not prevent the reviewer from starting",
                journal,
            )

    def test_exact_raw_secret_growth_is_the_only_admission_violation(
        self,
    ) -> None:
        repository_policy = _secret_admission_repository_policy_files(
            REPO_ROOT,
            CI_PROFILE,
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        policy = {
            **repository_policy,
            "SKILL.md": skill,
            "helper-contract.md": helper_contract,
            "pr-readiness.md": readiness,
        }
        for name, content in policy.items():
            with self.subTest(policy=name):
                self.assertIn("head_count <= base_count", content)

        self.assertIn("Only a first appearance or global count growth blocks", skill)
        self.assertIn("A first appearance or any growth blocks", helper_contract)
        self.assertIn("Do not derive Base64, hex, URL-encoded", skill)
        self.assertIn("No unembedded counter", helper_contract)
        self.assertIn("do not derive Base64 or other encodings", readiness)
        self.assertIn(
            "Report only head-side added locations",
            skill,
        )
        self.assertIn("Unchanged occurrences are omitted", helper_contract)
        self.assertIn("positive-delta candidates", readiness)
        if "AGENTS.md" in repository_policy:
            agents = repository_policy["AGENTS.md"]
            self.assertIn("Only a first appearance or count growth blocks", agents)
            self.assertIn("Do not derive Base64, hex, URL-encoded", agents)
        if "project journal" in repository_policy:
            journal = repository_policy["project journal"]
            self.assertIn("blocks only first appearance or growth", journal)
            self.assertIn(
                "does not derive canonical Base64, URL encoding, hexadecimal",
                journal,
            )
            self.assertIn(
                "only detectable additions for a candidate whose global count grows",
                journal,
            )

    def test_opaque_container_contract_uses_bounded_final_identities(
        self,
    ) -> None:
        policies = {
            "SKILL.md": (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8"),
            "helper-contract.md": (
                SKILL_ROOT / "references/helper-contract.md"
            ).read_text(encoding="utf-8"),
            "synthetic-token-fixtures.md": (
                SKILL_ROOT / "references/synthetic-token-fixtures.md"
            ).read_text(encoding="utf-8"),
        }
        for name, content in policies.items():
            with self.subTest(policy=name):
                self.assertIn("canonical blob OID alone", content)
                self.assertIn("blob paths are not retained", content)
                self.assertIn("100,000", content)
                self.assertIn("16 MiB", content)
                self.assertIn("base", content)
                self.assertIn("head", content)
                self.assertIn("source-WIP", content)
                self.assertNotIn("raw path plus blob OID", content)
                self.assertNotIn("retains raw path plus", content)

        runtime = (RUNTIME / "workspace.py").read_text(encoding="utf-8")
        self.assertIn(
            "MAX_SECRET_UNEXTRACTABLE_CONTAINER_IDENTITIES = MAX_SNAPSHOT_ENTRIES",
            runtime,
        )
        self.assertIn(
            "MAX_SECRET_UNEXTRACTABLE_PATH_IDENTITY_BYTES = 16 * 1024 * 1024",
            runtime,
        )

    def test_direct_secret_admission_is_required_without_a_reviewer(self) -> None:
        repository_policy = _secret_admission_repository_policy_files(
            REPO_ROOT,
            CI_PROFILE,
        )
        required_policy = {
            **repository_policy,
            "SKILL.md": (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8"),
            "pr-readiness.md": (SKILL_ROOT / "references/pr-readiness.md").read_text(
                encoding="utf-8"
            ),
            "review-lane-contracts.md": (
                SKILL_ROOT / "references/review-lane-contracts.md"
            ).read_text(encoding="utf-8"),
            "egress-consent.md": (
                SKILL_ROOT / "references/egress-consent.md"
            ).read_text(encoding="utf-8"),
        }
        for name, text in required_policy.items():
            with self.subTest(policy=name):
                lowered = text.lower()
                self.assertIn("secret-admission", text)
                self.assertIn("admission-only-no-reviewer", text)
                self.assertIn("exit", lowered)
                self.assertIn("`0`", text)
                self.assertIn("`1`", text)
                self.assertIn("`75`", text)
                self.assertNotIn(
                    "Obtain one low-level stateful helper state",
                    text,
                )

        helper = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("stateful final", helper)
        self.assertIn("stateful admission", helper)
        self.assertLess(
            helper.index("stateful final"), helper.index("stateful admission")
        )
        self.assertIn("retained only", helper)
        self.assertIn("starts no reviewer", helper)
        self.assertNotIn("only PR/master/merge-ready admission success", helper)

        readiness = required_policy["pr-readiness.md"]
        self.assertNotIn("same-state current-head exact-secret admission", readiness)
        self.assertIn("direct current-head exact-secret admission", readiness)
        for name in (
            "SKILL.md",
            "pr-readiness.md",
            "review-lane-contracts.md",
            "egress-consent.md",
        ):
            with self.subTest(cleanup_contract=name):
                self.assertIn("temporary_cleanup_status", required_policy[name])
        if "AGENTS.md" in repository_policy:
            self.assertIn(
                "temporary_cleanup_status",
                repository_policy["AGENTS.md"],
            )

    def test_stateful_secret_admission_is_a_separate_current_head_gate(self) -> None:
        helper = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("stateful final", helper)
        self.assertIn("stateful admission", helper)
        self.assertLess(
            helper.index("stateful final"), helper.index("stateful admission")
        )
        for exit_code in ("0", "1", "3", "75"):
            self.assertIn(f"exit `{exit_code}`", helper)
        self.assertIn(
            "successful optional helper-state check, not the required PR/master/merge-ready admission producer",
            helper,
        )
        self.assertIn(
            "schema-v5 `stateful final` / `stateful admission` compatibility contract",
            readiness,
        )
        self.assertIn(
            "compatible `stateful final` / `stateful admission` pair remains helper-only evidence",
            contracts,
        )
        self.assertNotIn(
            "the only result that permits PR/master/merge-ready",
            helper,
        )

    def test_admission_receipt_and_runner_policy_are_bound_to_the_launch(
        self,
    ) -> None:
        seal_source = inspect.getsource(state._seal_preflight_receipt)
        admission_source = inspect.getsource(state._admission_status_for_loaded_state)
        read_preflight_source = inspect.getsource(state._read_bound_preflight)
        start_source = inspect.getsource(state.start)
        run_state_source = inspect.getsource(state.run_state)
        cli_source = inspect.getsource(cli.main)

        self.assertEqual(state.BOUND_STATE_MARKER_SCHEMA_VERSION, 4)
        self.assertEqual(state.STATE_MARKER_SCHEMA_VERSION, 5)
        self.assertEqual(state.PREFLIGHT_RECEIPT_SCHEMA_VERSION, 1)
        self.assertLess(
            seal_source.index("validate_inherited_runner_lock_lease"),
            seal_source.index("_read_modern_bound_state_artifact"),
        )
        self.assertIn("hashlib.sha256(payload).hexdigest()", seal_source)
        self.assertIn("receipt = marker.preflight_receipt", read_preflight_source)
        self.assertIn("len(payload) != receipt.size", read_preflight_source)
        self.assertIn("runner-sealed", read_preflight_source)
        self.assertIn("legacy-state-no-preflight-receipt", admission_source)
        self.assertIn("preflight-unsealed", admission_source)

        for source in (start_source, cli_source):
            self.assertIn('"--reviewer"', source)
            self.assertIn('"--egress-consent"', source)
        self.assertIn("expected_reviewer=parsed.reviewer", cli_source)
        self.assertIn("expected_egress_consent=parsed.egress_consent", cli_source)
        self.assertIn("state_reviewer != expected_reviewer", run_state_source)
        self.assertIn(
            "state_egress_consent != expected_egress_consent",
            run_state_source,
        )

    def test_claude_runtime_and_clear_context_codex_agent_models_are_pinned(
        self,
    ) -> None:
        self.assertEqual(
            providers.CLAUDE_MODELS,
            ("claude-opus-4-8", "claude-opus-4-7"),
        )
        self.assertEqual(
            providers.COPILOT_MODELS,
            ("claude-opus-4.8", "claude-opus-4.7"),
        )
        self.assertEqual(
            providers.CLAUDE_EGRESS_CONSENTS,
            (
                "explicit-claude-review",
                "explicit-claude-with-copilot-fallback",
            ),
        )
        self.assertEqual(
            providers.COPILOT_EGRESS_CONSENTS,
            ("explicit-claude-with-copilot-fallback",),
        )
        self.assertEqual(
            providers.LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "supplied-diff-private-git",
        )
        self.assertFalse(providers.NAMED_LANE_ELIGIBLE)
        self.assertEqual(
            independent_constants.LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "supplied-diff-no-git",
        )
        self.assertFalse(independent_constants.NAMED_LANE_ELIGIBLE)
        independent_readme = (
            SCRIPTS / "independent_codex_pr_review" / "README.md"
        ).read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("review_contract: supplied-diff-no-git", independent_readme)
        self.assertIn("No findings.", independent_readme)
        self.assertIn(
            "review_contract: supplied-diff-private-git",
            helper_contract,
        )
        for contract_text in (independent_readme, helper_contract):
            self.assertIn("named_lane_eligible: false", contract_text)
        for candidate in (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/helper-contract.md",
        ):
            self.assertNotIn(
                "claude-sonnet-5",
                candidate.read_text(encoding="utf-8"),
                str(candidate),
            )
        with (SKILL_SCOPE_ROOT / "agents/reviewer.toml").open("rb") as handle:
            reviewer = tomllib.load(handle)
        self.assertEqual(reviewer["model"], "gpt-5.6-sol")
        self.assertEqual(reviewer["model_reasoning_effort"], "xhigh")
        self.assertEqual(reviewer["sandbox_mode"], "read-only")
        reviewer_instructions = reviewer["developer_instructions"]
        for anchor in (
            "required local Codex reviewer lane",
            "sole lane that satisfies a named single review",
            "separate clean Git workspace supplied by the orchestrator",
            "Keep it read-only",
            "exact prompt-provided authoritative review skill",
            "independently trusted control-plane bundle",
            "absolute path, version, and SHA-256 digest",
            "load that trusted review skill",
            "domain skill",
            "AGENTS.md",
            "project-guidance document",
            "exact base_sha and head_sha",
            "exact sanitized Git argv prefix",
            "/usr/bin/env -i",
            "never run bare `git`",
            "--no-ext-diff --no-textconv",
            "not a prebuilt or injected full diff",
            "obtain base_sha..head_sha metadata, changed paths, hunks",
            "state-changing MCP, Plugin, connector, GitHub",
            "read-only filesystem sandbox is not proof",
        ):
            self.assertIn(anchor, reviewer_instructions)

    def test_low_level_helper_local_login_runs_in_outer_safe_mode(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "ordinary local Claude login in trusted real `HOME` as the only authentication interface",
            skill,
        )
        self.assertIn(
            "helper authentication, apply precedence `ANTHROPIC_API_KEY` > "
            "`CLAUDE_CODE_OAUTH_TOKEN` > local login",
            skill,
        )
        self.assertIn(
            "An explicit API key or OAuth token bypasses helper local-login carrier access",
            skill,
        )
        self.assertIn("runs in safe mode", helper_contract)
        self.assertIn(
            "hardening-compatible `default` permission mode",
            helper_contract,
        )
        self.assertIn(
            "outer sandbox",
            helper_contract,
        )
        self.assertNotIn("safe mode with `dontAsk` permissions", helper_contract)
        self.assertIn("per-version signed manifest", helper_contract)
        self.assertIn("manifest checksum", helper_contract)
        self.assertIn("downloads.claude.ai", helper_contract)
        self.assertIn("deny-by-default Seatbelt profile", helper_contract)
        self.assertIn("current-account `Claude Code-credentials`", helper_contract)
        self.assertIn("helper-controlled proxy", helper_contract)
        self.assertIn(">=2.1.211,<3.0.0", helper_contract)
        self.assertIn("Linux and WSL2", helper_contract)
        self.assertNotIn("requires `ANTHROPIC_API_KEY`", skill)

    def test_helper_runtime_cwd_is_separate_from_host_workspace_binding(
        self,
    ) -> None:
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        validator_source = (SCRIPTS / "validate_claude_stream.py").read_text(
            encoding="utf-8"
        )

        self.assertEqual(str(claude_linux.SANDBOX_WORKSPACE), "/workspace")
        self.assertIn(
            "expected_runtime_cwd=str(sandbox_command.workspace_path)",
            provider_source,
        )
        self.assertIn("host_workspace_cwd=review.workspace_root", provider_source)
        self.assertIn("expected_cwd=expected_runtime_cwd", validator_source)
        self.assertIn("stream-reported runtime cwd as distinct inputs", helper_contract)
        self.assertIn(
            "Linux and WSL2 bind the reported runtime cwd to `/workspace`",
            helper_contract,
        )
        self.assertIn(
            "named-direct structured-tool path scope remains bound to the host clean worktree",
            helper_contract,
        )

    def test_claude_auth_carriers_refresh_without_a_freshness_gate(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )

        egress_consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        repository_policy_files = _claude_auth_repository_policy_files(
            REPO_ROOT,
            CI_PROFILE,
        )

        self.assertEqual(claude_capabilities.CLAUDE_MINIMUM_VERSION, (2, 1, 211))
        self.assertEqual(claude_linux.DEFAULT_CREDENTIAL_VALIDITY_SECONDS, 0.0)
        self.assertFalse(hasattr(providers, "CLAUDE_AUTH_EXPIRY_MARGIN_SECONDS"))
        self.assertFalse(
            hasattr(providers, "CLAUDE_ATTEMPT_CREDENTIAL_VALIDITY_SECONDS")
        )

        attempt_source = inspect.getsource(
            providers._claude_attempt
        ) + inspect.getsource(providers._claude_attempt_with_output)
        pwd_home_source = inspect.getsource(providers._claude_pwd_home)
        select_source = inspect.getsource(providers._select_claude_macos_credential)
        validate_source = inspect.getsource(providers._validate_claude_local_credential)
        macos_runtime_source = (
            inspect.getsource(providers._claude_keychain_runtime)
            + inspect.getsource(providers._claude_keychain_runtime_coordinated)
            + inspect.getsource(providers._claude_keychain_runtime_selected)
        )
        macos_persist_source = inspect.getsource(
            providers._persist_claude_macos_refreshed_credential
        ) + inspect.getsource(providers._persist_claude_macos_refreshed_credential_impl)
        macos_recovery_report_source = inspect.getsource(
            providers._record_claude_secondary_persistence_failure
        )
        run_review_source = inspect.getsource(providers.run_review)
        auth_outcome_source = inspect.getsource(providers._finish_claude_auth_required)
        linux_runtime_source = inspect.getsource(providers._claude_linux_review_runtime)
        linux_command_source = inspect.getsource(claude_linux.build_sandbox_command)
        keychain_write_source = inspect.getsource(
            providers._write_claude_keychain_credential
        )
        file_write_source = inspect.getsource(providers._write_claude_file_credential)
        linux_write_source = inspect.getsource(
            claude_linux._writeback_refreshed_credential_impl
        )
        linux_staging_source = inspect.getsource(claude_linux.stage_claude_credentials)
        linux_anchored_staging_source = inspect.getsource(
            claude_linux._stage_claude_credentials_anchored
        )
        refresh_lock_source = inspect.getsource(
            claude_refresh_lock.acquire_claude_refresh_lock
        )
        staged_lock_recovery_source = inspect.getsource(
            claude_refresh_lock.recover_abandoned_staged_claude_refresh_locks
        )

        self.assertNotIn("_warm_claude_local_login", attempt_source)
        self.assertNotIn("authentication-preflight-entitlement", attempt_source)
        self.assertNotIn("freshness-verified", attempt_source)
        self.assertIn("_prepare_claude_tls_environment", attempt_source)
        self.assertIn("_claude_keychain_runtime", attempt_source)
        self.assertIn("_claude_linux_review_runtime", attempt_source)

        self.assertIn("pwd.getpwuid(os.getuid()).pw_dir", pwd_home_source)
        self.assertNotIn('os.environ.get("HOME")', pwd_home_source)
        self.assertIn("_read_claude_keychain_credential", select_source)
        self.assertIn("_read_claude_macos_file_credential", select_source)
        self.assertIn("selected = max(", select_source)
        self.assertIn("candidate.expires_at_ms", select_source)
        self.assertIn("selected.carrier_snapshot", select_source)
        self.assertIn("refreshToken", validate_source)
        self.assertIn(
            "_persist_claude_macos_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "_retain_claude_macos_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "_replace_claude_macos_recovery_credential",
            macos_runtime_source,
        )
        self.assertIn(
            "durable-recovery-before-ack",
            macos_runtime_source,
        )
        self.assertIn("commit_pending", macos_runtime_source)
        self.assertIn(
            "update_callback=stage_refreshed_credential",
            macos_runtime_source,
        )
        self.assertNotIn(
            "update_callback=accept_refreshed_credential",
            macos_runtime_source,
        )
        self.assertIn("_write_claude_keychain_credential", macos_persist_source)
        self.assertIn("_write_claude_file_credential", macos_persist_source)
        self.assertNotIn("require_unexpired=True", macos_runtime_source)
        self.assertNotIn("require_unexpired=True", macos_persist_source)
        self.assertIn(
            'authentication_report["recovery_cleanup_artifact"]',
            macos_recovery_report_source,
        )

        self.assertIn("stage_claude_credentials", linux_runtime_source)
        self.assertIn("writer_started", linux_runtime_source)
        self.assertIn("writer_quiescent", linux_runtime_source)
        self.assertIn(
            "on_process_starting=writer_start.publish_starting",
            attempt_source,
        )
        self.assertIn(
            "on_process_started=writer_start.publish_started",
            attempt_source,
        )
        self.assertIn("writer_quiescent.set()", attempt_source)
        self.assertIn(
            "retain_for_recovery",
            linux_staging_source + linux_anchored_staging_source,
        )
        self.assertIn("writer_quiescent is not True", staged_lock_recovery_source)
        self.assertIn("reversed(locks)", staged_lock_recovery_source)
        self.assertNotIn("math.nextafter", linux_runtime_source)
        self.assertNotIn("staged.expires_at_ms <= time.time()", linux_runtime_source)
        self.assertNotIn("_require_fresh_claude_linux_credential", run_review_source)
        self.assertEqual(str(claude_linux.SANDBOX_AUTH_ROOT), "/auth")
        self.assertEqual(str(claude_linux.SANDBOX_CONFIG), "/auth/config")
        self.assertIn(
            '"CLAUDE_CONFIG_DIR": str(SANDBOX_CONFIG)',
            linux_command_source,
        )

        carrier_policy_files = {
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
        }
        for name in ("README.md", "project journal"):
            if policy := repository_policy_files.get(name):
                carrier_policy_files[name] = policy
        for name, policy in carrier_policy_files.items():
            with self.subTest(policy=name):
                normalized = policy.lower()
                self.assertIn("/auth/config", policy)
                self.assertIn("final drain", normalized)
                self.assertIn("recovery carrier", normalized)
                self.assertNotIn("read(//config", normalized)
                self.assertNotIn("at `/config`", policy)
                self.assertNotIn("mounts only that carrier at `/config`", policy)

        macos_recovery_policy_files = {
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
        }
        if journal := repository_policy_files.get("project journal"):
            macos_recovery_policy_files["project journal"] = journal
        for name, policy in macos_recovery_policy_files.items():
            with self.subTest(macos_recovery_policy=name):
                normalized = policy.lower()
                self.assertIn("macos", normalized)
                self.assertIn("private recovery carrier", normalized)
                self.assertIn("copilot fallback", normalized)

        macos_quiescence_policy_files = {
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
            **repository_policy_files,
        }
        for name, policy in macos_quiescence_policy_files.items():
            with self.subTest(macos_quiescence_policy=name):
                normalized = policy.lower()
                self.assertRegex(normalized, r"quiesc(?:e|ence)")
                self.assertIn("recovery_cleanup_artifact", policy)
                self.assertIn("incomplete", normalized)
                self.assertNotIn("before acknowledging", normalized)
                self.assertNotIn("every accepted rotation", normalized)
                self.assertNotIn(
                    "persist macos broker rotations before",
                    normalized,
                )

        macos_terminal_reserve_policy_files = {
            "helper-contract.md": helper_contract,
            "claude-runtime-trust.md": runtime_trust,
            **repository_policy_files,
        }
        for name, policy in macos_terminal_reserve_policy_files.items():
            with self.subTest(macos_terminal_reserve_policy=name):
                normalized = policy.lower()
                self.assertIn("admitted to durable staging", normalized)
                self.assertIn("last generation and 1 mib", normalized)
                self.assertNotIn(
                    "reaching either journal cap nacks the generation",
                    normalized,
                )
                self.assertNotIn(
                    "nack the generation before filesystem work",
                    normalized,
                )

        self.assertIn(
            "durably stage that current update in the terminal recovery slot",
            runtime_trust,
        )
        self.assertIn(
            "NACK later requests before their callbacks or filesystem work",
            runtime_trust,
        )

        protocol = claude_refresh_lock.CLAUDE_REFRESH_LOCK_PROTOCOL_2_1_211
        self.assertEqual(protocol.primary_lock_name, ".oauth_refresh.lock")
        self.assertEqual(protocol.legacy_suffix, ".lock")
        self.assertEqual(protocol.stale_seconds, 60.0)
        self.assertEqual(protocol.update_seconds, 5.0)
        self.assertEqual(
            set(claude_refresh_lock.CERTIFIED_CLAUDE_REFRESH_LOCK_ARTIFACTS),
            EXPECTED_CLAUDE_2_1_211_LOCK_ARTIFACTS,
        )
        self.assertLess(
            refresh_lock_source.index('label="primary"'),
            refresh_lock_source.index('label="legacy"'),
        )
        for write_source in (keychain_write_source, file_write_source):
            self.assertIn("claude_refresh_lock", write_source)
            self.assertIn("_claude_macos_carriers_match", write_source)
            self.assertIn("refresh_lock.assert_held()", write_source)
            self.assertIn("refresh_lock_protocol", write_source)
        self.assertIn("acquire_claude_refresh_lock", linux_write_source)
        self.assertIn("refresh_lock.assert_held()", linux_write_source)
        self.assertIn("refresh_lock_protocol", linux_write_source)
        self.assertIn("_certified_claude_refresh_lock_protocol", attempt_source)
        self.assertIn(
            "authentication_source = _claude_authentication_source(attempt_env)",
            attempt_source,
        )
        self.assertIn('authentication_source != "local-login"', attempt_source)

        self.assertIn('"phase": "blocked-authentication"', auth_outcome_source)
        self.assertIn("CLAUDE_AUTH_LOGIN_ACTION", auth_outcome_source)
        self.assertIn("_finish_claude_auth_required", run_review_source)
        self.assertIn("validate_external_workspace", run_review_source)
        self.assertIn(
            "review workspace containment and integrity checks passed",
            run_review_source,
        )
        self.assertIn("secret-delta status is evaluated separately", run_review_source)

        current_policy = "\n".join(
            (
                skill,
                helper_contract,
                runtime_trust,
                egress_consent,
                repository_policy_files.get("AGENTS.md", ""),
            )
        )
        self.assertIn(">=2.1.211,<3.0.0", current_policy)
        self.assertIn("pwd.getpwuid(os.getuid())", current_policy)
        self.assertIn("empirically compatible", current_policy)
        self.assertIn("not an officially guaranteed storage contract", current_policy)
        self.assertIn("guarded writeback", current_policy)
        self.assertIn("not an atomic compare-and-swap guarantee", current_policy)
        self.assertIn("primary `.oauth_refresh.lock`", current_policy)
        self.assertIn("legacy sibling lock", current_policy)
        self.assertIn("bypass both locks", current_policy)
        self.assertIn("credential-lock protocol catalog", current_policy)
        self.assertIn("5-second heartbeat", current_policy)
        self.assertIn("both carriers", current_policy)
        self.assertIn("inspection-inconclusive", current_policy)
        self.assertIn("Access-token expiry alone is not login expiry", current_policy)
        self.assertIn("blocked-authentication", current_policy)
        self.assertIn("claude auth login", current_policy)
        for policy in (helper_contract, runtime_trust):
            self.assertIn("claude auth login", policy)
            self.assertIn("ANTHROPIC_API_KEY", policy)
            self.assertIn("unset or replace", policy)
        self.assertIn(
            "GitHub Copilot requires a separate explicit request", current_policy
        )
        self.assertIn("does not silently change providers", current_policy)
        self.assertIn("model entitlement", current_policy)
        self.assertNotIn("has no usable local/API authentication", current_policy)
        self.assertNotIn("1920", current_policy)

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
        cli_denies = set(claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS.split(","))
        self.assertTrue({"Grep", "Glob"}.issubset(cli_denies))
        self.assertIn(
            "Read(//auth/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertIn(
            "Read(//proc/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )
        self.assertNotIn(
            "Read(/auth/**)",
            claude_linux.CLAUDE_LINUX_FILE_TOOL_DENY_RULES,
        )

    def test_direct_and_helper_claude_modes_keep_distinct_home_contracts(
        self,
    ) -> None:
        policies = _current_claude_contract_files()
        skill = policies["SKILL.md"]
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        helper = policies["helper-contract.md"]

        for phrase in (
            "real `HOME`",
            "ordinary local Claude CLI login",
            "trusted control plane",
            "does not use the low-level helper's credential broker",
        ):
            self.assertIn(phrase, canonical)
        for phrase in (
            "helper-owned detached worktree",
            "private minimal Git",
            "review_contract: supplied-diff-private-git",
            "named_lane_eligible: false",
        ):
            self.assertIn(phrase, skill)
        for phrase in (
            "helper-owned outer sandbox",
            "credential-lock protocol catalog",
            "recovery carrier",
            "guarded writeback",
        ):
            self.assertIn(phrase, helper)
        self.assertEqual(
            providers.LOW_LEVEL_HELPER_REVIEW_CONTRACT,
            "supplied-diff-private-git",
        )
        self.assertFalse(providers.NAMED_LANE_ELIGIBLE)

        self.assertIn('"autoAllowBashIfSandboxed": false', canonical)
        self.assertIn('"allowUnsandboxedCommands": false', canonical)
        helper_arguments = providers._claude_review_arguments(
            model="claude-opus-4-8",
            settings="{}",
            linux=False,
        )
        self.assertEqual(
            helper_arguments[helper_arguments.index("--permission-mode") + 1],
            "default",
        )
        self.assertEqual(
            helper_arguments[helper_arguments.index("--tools") + 1],
            "Read,Grep,Glob",
        )
        self.assertIn(
            "Bash",
            helper_arguments[helper_arguments.index("--disallowedTools") + 1].split(
                ","
            ),
        )
        self.assertIn("`Read`, `Grep`, `Glob`, and sandboxed `Bash`", skill)
        self.assertIn("native sandbox", skill)

    def test_claude_auth_contracts_delegate_to_verified_cli(self) -> None:
        policies = _current_claude_contract_files()
        combined = "\n".join(policies.values())
        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")

        helper_precedence = (
            "`ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local login"
        )
        self.assertIn(
            "ordinary local Claude login in trusted real `HOME` as the only "
            "authentication interface",
            policies["SKILL.md"],
        )
        self.assertIn(helper_precedence, policies["SKILL.md"])
        if "README.md" in policies:
            self.assertIn(
                "accepts only ordinary local login in trusted real `HOME`",
                policies["README.md"],
            )
            self.assertIn(helper_precedence, policies["README.md"])
            self.assertIn(
                "`ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`",
                policies["README.md"],
            )
        self.assertIn("ANTHROPIC_API_KEY", provider_source)
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", provider_source)
        self.assertIn("blocked-authentication", combined)
        self.assertIn("claude auth login", combined)
        self.assertIn("unset or replace `ANTHROPIC_API_KEY`", combined)
        self.assertIn("unset or replace `CLAUDE_CODE_OAUTH_TOKEN`", combined)
        self.assertIn("opaque", combined)

    def test_direct_claude_does_not_inherit_helper_credential_transactions(
        self,
    ) -> None:
        direct_policy = {
            "SKILL.md": (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8"),
            "canonical-claude-lane.md": (
                SKILL_ROOT / "references/canonical-claude-lane.md"
            ).read_text(encoding="utf-8"),
            "review-lane-contracts.md": (
                SKILL_ROOT / "references/review-lane-contracts.md"
            ).read_text(encoding="utf-8"),
        }
        for name, content in direct_policy.items():
            with self.subTest(direct_policy=name):
                self.assertIn("real `HOME`", content)
                self.assertIn("direct", content)
        self.assertIn(
            "does not use the low-level helper's credential broker",
            direct_policy["canonical-claude-lane.md"],
        )
        self.assertIn(
            "do not apply to this direct lane",
            direct_policy["review-lane-contracts.md"],
        )

        runtime_source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (RUNTIME / "providers.py", RUNTIME / "claude_linux.py")
        )
        for symbol in (
            "_prepare_claude_keychain_broker",
            "_claude_keychain_runtime",
            "_persist_claude_macos_refreshed_credential",
            "_write_claude_keychain_credential",
            "stage_claude_credentials",
            "acquire_claude_refresh_lock",
        ):
            with self.subTest(symbol=symbol):
                self.assertIn(symbol, runtime_source)

        helper_policy = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        for helper_term in (
            "credential-lock protocol catalog",
            "recovery carrier",
            "/auth/config",
            "guarded writeback",
            "broker `W` generation",
        ):
            with self.subTest(helper_term=helper_term):
                self.assertIn(helper_term, helper_policy)

    def test_workspace_defaults_clean_and_wip_is_explicit_diagnostic_only(
        self,
    ) -> None:
        cli_source = (RUNTIME / "cli.py").read_text(encoding="utf-8")
        workspace_source = (RUNTIME / "workspace.py").read_text(encoding="utf-8")
        policies = _current_claude_contract_files()

        self.assertIn("--include-source-wip", cli_source)
        self.assertIn("include_source_wip", cli_source + workspace_source)
        for name in ("SKILL.md", "helper-contract.md"):
            policy = policies[name]
            with self.subTest(policy=name):
                self.assertIn("--include-source-wip", policy)
                self.assertIn("staged", policy)
                self.assertIn("unstaged", policy)
                self.assertIn("untracked", policy)

        helper = policies["helper-contract.md"]
        self.assertIn("private-minimal-Git", helper)
        self.assertIn("WIP digest", helper)
        self.assertIn("source checkout", helper)
        self.assertIn("original source `HEAD`", helper)
        self.assertIn("WIP deletion or reversion", helper)
        self.assertIn(
            "match exactly between the source `HEAD` tree and active index",
            helper,
        )
        self.assertIn(
            "Top-level source queries ignore initialized submodule worktree state",
            helper,
        )
        self.assertIn(
            "never read nested content or local Git configuration",
            helper,
        )

        readiness = policies["pr-readiness.md"]
        self.assertIn("detached clean lane worktrees", readiness)
        self.assertIn("<merge_base>..HEAD", readiness)
        self.assertNotIn("--include-source-wip", readiness)

        consent = policies["egress-consent.md"]
        self.assertIn("--include-source-wip", consent)
        self.assertIn("Clean-head helper approval", consent)
        self.assertIn("Source-WIP helper approval", consent)
        self.assertIn("content_variant=head", consent)
        self.assertIn("content_variant=source-wip", consent)
        self.assertIn("untracked private files", consent)
        self.assertIn("home-directory content", consent)

    def test_review_workspace_and_state_use_external_system_temp_root(self) -> None:
        workspace_source = (RUNTIME / "workspace.py").read_text(encoding="utf-8")
        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        combined = "\n".join(_current_claude_contract_files().values())

        self.assertIn('REVIEW_ROOT_BASE = pathlib.Path("/tmp")', workspace_source)
        self.assertIn(
            'REVIEW_USER_ROOT_PREFIX = "codex-isolated-review-uid-"',
            workspace_source,
        )
        self.assertIn(
            "hashlib.sha256(os.fsencode(str(canonical_source))).hexdigest()",
            workspace_source,
        )
        self.assertIn(
            "helper review root must be outside the source repository",
            workspace_source,
        )
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "/tmp/codex-isolated-review-uid-<effective-uid>/"
            "<sha256(canonical-source-path)>/isolated-review-*",
            helper_contract,
        )
        self.assertIn(
            "Source-local `.codex-tmp` remains only a schema-v1-to-v4 "
            "legacy compatibility layout",
            helper_contract,
        )
        self.assertNotIn(
            "source_root/.codex-tmp/isolated-review-*",
            helper_contract,
        )
        self.assertIn("_review_root_for_source(canonical_source)", provider_source)
        self.assertIn("container_root.parent != review_root", provider_source)
        for phrase in (
            "system temporary root `/tmp`",
            "outside the source checkout",
            "effective UID",
            "canonical source path",
        ):
            self.assertIn(phrase, combined)

    def test_helper_wip_requires_separate_consent_while_named_egress_excludes_it(
        self,
    ) -> None:
        helper = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("separate explicit consent", helper)
        self.assertIn("--include-source-wip", helper)
        self.assertIn("nonignored untracked", helper)
        self.assertIn("WIP evidence is diagnostic only", helper)
        self.assertIn("untracked private files", consent)
        self.assertIn("home-directory content", consent)
        self.assertIn("hidden local-only artifacts", consent)
        self.assertIn("--include-source-wip", consent)

        provider_source = (RUNTIME / "providers.py").read_text(encoding="utf-8")
        for field in (
            "content_variant",
            "include_source_wip",
            "snapshot_tree_sha",
            "scope_identity",
        ):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', provider_source)
                self.assertIn(field, helper)
                self.assertIn(field, consent)

        self.assertIn("Clean-head approval:", helper)
        self.assertIn("Source-WIP approval:", helper)
        for document in (helper, consent):
            with self.subTest(document=document[:32]):
                self.assertIn("staged, unstaged, and nonignored untracked", document)
                self.assertIn(
                    "ignored untracked files and source content not captured by the "
                    "WIP snapshot",
                    document,
                )
                self.assertIn("content_variant=head", document)
                self.assertIn("content_variant=source-wip", document)
                self.assertIn("`false` for `content_variant: head`", document)
                self.assertIn(
                    "`true` only for `content_variant: source-wip`",
                    document,
                )

        source_wip_approval = consent.split(
            "### Source-WIP helper approval",
            maxsplit=1,
        )[1].split("Do not shorten this", maxsplit=1)[0]
        self.assertNotIn(
            "This excludes automatic discovery of reviewer/runtime authentication "
            "credentials, untracked files",
            source_wip_approval,
        )

    def test_ci_targets_only_the_canonical_runtime_and_tests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("review-orchestration-playbook/tests", workflow)
        self.assertNotIn("external-review-playbook", workflow)
        self.assertNotIn("copilot-review-playbook", workflow)
        if CI_PROFILE == "canonical":
            compatibility_path = REPO_ROOT / ".github/workflows/codex-review-gate.yml"
            compatibility = compatibility_path.read_text(encoding="utf-8")
            self.assertEqual(
                compatibility_path.read_bytes(),
                COMPATIBILITY_WORKFLOW_FIXTURE.read_bytes(),
                "compatibility status workflow differs from the reviewed safety snapshot",
            )
            for anchor in (
                "Codex Review Gate Compatibility Status",
                "pull_request_target:",
                "types: [opened, reopened, synchronize, ready_for_review]",
                "workflow_dispatch:",
                "permissions: {}",
                "jobs:\n  compatibility-status:",
                "if: github.event_name == 'pull_request_target'",
                "name: codex/review-gate compatibility publisher",
                "permissions:\n      statuses: write",
                "GH_TOKEN: ${{ github.token }}",
                "HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
                "REPOSITORY: ${{ github.repository }}",
                'gh api --method POST "repos/${REPOSITORY}/statuses/${HEAD_SHA}"',
                "backfill-open-pull-requests:",
                "if: github.event_name == 'workflow_dispatch'",
                "Backfill exact current pull request heads",
                "pull-requests: read\n      statuses: write",
                "readonly MAX_ENUMERATION_PASSES=6",
                "for ((pass = 1; pass <= MAX_ENUMERATION_PASSES; pass++)); do",
                '"repos/${REPOSITORY}/pulls?state=all&sort=created&direction=asc&per_page=100"',
                "([.[][]] | sort_by(.number)) as $pulls",
                'map(select(.state == "open") | "\\(.number)\\t\\(.head.sha)")',
                '"RETRY_PAGINATION"',
                "validated_head_shas=()",
                'gh api --method POST "repos/${REPOSITORY}/statuses/${head_sha}"',
                '"${current_snapshot}" == "${previous_snapshot}"',
                "did not stabilize after ${MAX_ENUMERATION_PASSES} authenticated enumeration passes",
                '"${GITHUB_REF}" != "refs/heads/${DEFAULT_BRANCH}"',
                "-f state=success",
                "-f context=codex/review-gate",
                "Compatibility only; no reviewer or review lane.",
            ):
                self.assertIn(anchor, compatibility)
            self.assertEqual(compatibility.count("\n  compatibility-status:\n"), 1)
            self.assertEqual(
                compatibility.count("\n  backfill-open-pull-requests:\n"), 1
            )
            self.assertEqual(compatibility.count("gh api --paginate --slurp"), 1)
            enumeration = compatibility.index("gh api --paginate --slurp")
            publication = compatibility.index(
                'gh api --method POST "repos/${REPOSITORY}/statuses/${head_sha}"'
            )
            stabilization = compatibility.index(
                '"${current_snapshot}" == "${previous_snapshot}"'
            )
            self.assertLess(enumeration, stabilization)
            self.assertLess(stabilization, publication)
            self.assertNotIn("workflow_dispatch:\n    inputs:", compatibility)
            for forbidden in (
                "pull_request:",
                "issue_comment:",
                "pull_request_review:",
                "schedule:",
                "pull-requests: write",
                "issues: write",
                "codex-review-gate-action",
                "@codex review",
                "\n      - uses:",
                "actions/checkout",
                "github.sha",
                "github.event.inputs",
                "pulls?state=open&",
            ):
                self.assertNotIn(forbidden, compatibility)

    def test_ci_matches_the_reviewed_repo_profile_snapshot(self) -> None:
        actual = (REPO_ROOT / ".github/workflows/ci.yml").read_bytes()
        expected = (CI_FIXTURE_ROOT / f"{CI_PROFILE}.yml").read_bytes()

        self.assertEqual(
            actual,
            expected,
            f"CI workflow differs from reviewed {CI_PROFILE} snapshot",
        )

    def test_ci_contract_context_accepts_only_supported_layouts(self) -> None:
        cases = (
            (
                pathlib.Path("/repo/skills/review-orchestration-playbook"),
                (pathlib.Path("/repo"), "canonical"),
            ),
            (
                pathlib.Path(
                    "/repo/personal_codex/skills/review-orchestration-playbook"
                ),
                (pathlib.Path("/repo"), "private"),
            ),
        )
        for skill_root, expected in cases:
            with self.subTest(skill_root=skill_root):
                self.assertEqual(_ci_contract_context(skill_root), expected)

        with self.assertRaisesRegex(AssertionError, "unsupported review skill layout"):
            _ci_contract_context(pathlib.Path("/repo/custom/review-playbook"))

    def test_repository_policy_scope_matches_distribution_profile(self) -> None:
        repo_root = pathlib.Path("/repo")

        self.assertEqual(
            _repository_policy_scope_root(repo_root, "canonical"),
            repo_root,
        )
        self.assertEqual(
            _repository_policy_scope_root(repo_root, "private"),
            repo_root / "personal_codex",
        )
        self.assertEqual(
            _repository_agents_path(repo_root, "canonical"),
            repo_root / "AGENTS.md",
        )
        self.assertEqual(
            _repository_agents_path(repo_root, "private"),
            repo_root / "personal_codex/AGENTS.md",
        )
        with self.assertRaisesRegex(
            AssertionError,
            "unsupported repository policy profile",
        ):
            _repository_policy_scope_root(repo_root, "unknown")

    def test_ci_contract_carries_every_reviewed_profile_snapshot(self) -> None:
        self.assertEqual(
            set(CI_PROFILE_BY_SKILL_LAYOUT.values()),
            {"canonical", "private"},
        )
        for profile in CI_PROFILE_BY_SKILL_LAYOUT.values():
            with self.subTest(profile=profile):
                self.assertTrue((CI_FIXTURE_ROOT / f"{profile}.yml").is_file())

    def test_reviewed_ci_snapshots_use_source_only_python_checks(self) -> None:
        expected_cache_guards = {"canonical": 2, "private": 4}
        for profile, guard_count in expected_cache_guards.items():
            with self.subTest(profile=profile):
                workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(
                    encoding="utf-8"
                )
                self.assertIn('PYTHONDONTWRITEBYTECODE: "1"', workflow)
                self.assertNotIn("python3 -m py_compile", workflow)
                self.assertNotIn("python3 -m compileall", workflow)
                self.assertIn(
                    'compile(pathlib.Path(path).read_bytes(), path, "exec")',
                    workflow,
                )
                self.assertIn(
                    'compile(path.read_bytes(), str(path), "exec")',
                    workflow,
                )
                self.assertEqual(
                    workflow.count("- name: Require source-only Python tree"),
                    guard_count,
                )

    def test_claude_auth_policy_files_match_distribution_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir)
            (repo_root / "README.md").write_text("unrelated\n", encoding="utf-8")

            self.assertEqual(
                _claude_auth_repository_policy_files(repo_root, "private"),
                {},
            )
            with self.assertRaises(FileNotFoundError):
                _claude_auth_repository_policy_files(repo_root, "canonical")
            with self.assertRaisesRegex(
                AssertionError,
                "unsupported repository policy profile",
            ):
                _claude_auth_repository_policy_files(repo_root, "unknown")

    def test_secret_admission_policy_files_match_distribution_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_root = pathlib.Path(temp_dir)

            self.assertEqual(
                _secret_admission_repository_policy_files(repo_root, "private"),
                {},
            )
            with self.assertRaises(FileNotFoundError):
                _secret_admission_repository_policy_files(repo_root, "canonical")
            with self.assertRaisesRegex(
                AssertionError,
                "unsupported repository policy profile",
            ):
                _secret_admission_repository_policy_files(repo_root, "unknown")

    def test_reviewed_ci_snapshots_keep_the_intended_status_guards(self) -> None:
        canonical = (CI_FIXTURE_ROOT / "canonical.yml").read_text(encoding="utf-8")
        private = (CI_FIXTURE_ROOT / "private.yml").read_text(encoding="utf-8")

        self.assertIn(
            """  test:
    name: test
    if: ${{ always() }}
    needs:
      - platform_tests
      - broker_reproducibility
      - independent_supervisor_tests
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
          BROKER_REPRODUCIBILITY_RESULT: ${{ needs.broker_reproducibility.result }}
          INDEPENDENT_SUPERVISOR_RESULT: ${{ needs.independent_supervisor_tests.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
          test "$BROKER_REPRODUCIBILITY_RESULT" = "success"
          test "$INDEPENDENT_SUPERVISOR_RESULT" = "success"
""",
            canonical,
        )
        self.assertIn(
            """  test:
    name: test
    if: ${{ always() }}
    needs:
      - platform_tests
      - python-39-compatibility
      - platform-safety
      - broker_reproducibility
      - independent_supervisor_tests
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
          PYTHON_39_RESULT: ${{ needs.python-39-compatibility.result }}
          PLATFORM_SAFETY_RESULT: ${{ needs.platform-safety.result }}
          BROKER_REPRODUCIBILITY_RESULT: ${{ needs.broker_reproducibility.result }}
          INDEPENDENT_SUPERVISOR_RESULT: ${{ needs.independent_supervisor_tests.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
          test "$PYTHON_39_RESULT" = "success"
          test "$PLATFORM_SAFETY_RESULT" = "success"
          test "$BROKER_REPRODUCIBILITY_RESULT" = "success"
          test "$INDEPENDENT_SUPERVISOR_RESULT" = "success"
""",
            private,
        )

    def test_completed_trust_port_journal_uses_current_claude_range(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("completed canonical project journal is not mirrored")
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-16-review-helper-trust-port-821601.md"
        ).read_text(encoding="utf-8")

        self.assertIn("`>=2.1.211,<3.0.0`", journal)
        self.assertNotIn(">=2.1.187", journal)

    def test_runtime_state_journal_matches_deterministic_identity(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("canonical project journal is not mirrored")
        runner_path = (
            SCRIPTS / "independent_codex_pr_review/tests/"
            "run_required_deterministic_supervisor.py"
        )
        assignments: dict[str, object] = {}
        for statement in ast.parse(runner_path.read_text(encoding="utf-8")).body:
            if (
                isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id
                in {"EXPECTED_TEST_COUNT", "EXPECTED_TEST_ID_SHA256"}
            ):
                assignments[statement.targets[0].id] = ast.literal_eval(statement.value)

        expected_count = assignments["EXPECTED_TEST_COUNT"]
        expected_sha256 = assignments["EXPECTED_TEST_ID_SHA256"]
        self.assertIsInstance(expected_count, int)
        self.assertIsInstance(expected_sha256, str)
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-27-review-runtime-state-root-rsr001.md"
        ).read_text(encoding="utf-8")
        project_state = (REPO_ROOT / "docs/PROJECT_STATE.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            f"passed {expected_count}/{expected_count}",
            journal,
        )
        self.assertIn(
            f"reviewed {expected_count}-test selected identity",
            journal,
        )
        self.assertIn(f"`{expected_sha256}`", journal)
        self.assertIn(
            "Latest workstream: "
            "`docs/project_journal/2026/07/"
            "2026-07-27-review-runtime-state-root-rsr001.md`",
            project_state,
        )

    def test_broker_reproducibility_never_runs_checkout_code_as_root(self) -> None:
        script = (SCRIPTS / "build_claude_keychain_broker_macos.sh").read_text(
            encoding="utf-8"
        )
        for profile in ("canonical", "private"):
            workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(encoding="utf-8")
            start = workflow.index("  broker_reproducibility:")
            end = workflow.index("\n  independent_supervisor_tests:", start)
            broker_job = workflow[start:end]
            with self.subTest(profile=profile):
                self.assertNotIn("sudo", broker_job)
                self.assertNotIn("/private/var/root", broker_job)
                self.assertIn("--check", broker_job)
                self.assertIn("runs-on: macos-26", broker_job)

        self.assertNotIn("require_root_sealed", script)
        self.assertNotIn("EUID", script)
        self.assertNotIn("--output", script)
        self.assertIn("not a security boundary", script)
        self.assertIn("byte-reproducible", script)
        for mode in ("DEVELOPER", "HOSTED"):
            for tool in (
                "CLANG",
                "LD",
                "LIPO",
                "VTOOL",
                "CODESIGN_ALLOCATE",
                "CODESIGN",
            ):
                self.assertIn(f'EXPECTED_{mode}_{tool}_SHA256="', script)
        self.assertIn('if [[ "$mode" == "hosted-check" ]]', script)
        self.assertIn("initialize_expected_tool_digests", script)

    def test_independent_supervisor_ci_separates_hosted_and_live_gates(self) -> None:
        live_runner = (
            SCRIPTS
            / "independent_codex_pr_review/tests/run_required_no_child_profile.py"
        ).read_text(encoding="utf-8")
        deterministic_runner = (
            SCRIPTS / "independent_codex_pr_review/tests/"
            "run_required_deterministic_supervisor.py"
        ).read_text(encoding="utf-8")
        hosted_probe = (
            SCRIPTS / "independent_codex_pr_review/tests/"
            "run_hosted_no_child_fail_closed.py"
        ).read_text(encoding="utf-8")
        pr_readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        for runner in (live_runner, deterministic_runner):
            self.assertIn("result.skipped,", runner)
            self.assertIn("result.wasSuccessful()", runner)
            self.assertIn("result.testsRun !=", runner)
            self.assertIn("result.expectedFailures", runner)
            self.assertIn("result.unexpectedSuccesses", runner)
        self.assertIn("NoChildProfileDarwinIntegrationTests", live_runner)
        self.assertIn("CodexExecutableAuthenticationTests", live_runner)
        self.assertIn("REQUIRE_LIVE_NO_CHILD_PROFILE_ENV", live_runner)
        self.assertNotIn("GITHUB_HOSTED_RUNTIME_PIN", live_runner)
        self.assertIn("expected_count != 9", live_runner)
        self.assertIn("len(REQUIRED_TEST_KEYS) != expected_count", live_runner)
        self.assertIn("EXPECTED_TEST_COUNT = 604", deterministic_runner)
        self.assertIn("EXPECTED_TEST_ID_SHA256 =", deterministic_runner)
        self.assertIn("selected_identity_sha256 !=", deterministic_runner)
        self.assertIn("excluded_keys != REQUIRED_TEST_KEYS", deterministic_runner)
        self.assertIn("if duplicate_keys:", deterministic_runner)
        self.assertIn("expected_discovered_count", deterministic_runner)
        self.assertIn("_test_key", deterministic_runner)
        for contract in (
            "return-before-ownership publisher",
            "launch `CALL`-to-caller-`STORE`",
            "pending custody containing the random name",
            "`mkdir` syscall-result boundary",
            "callee-return-to-caller-`STORE` interruption window",
            "manifest `CALL`-to-`STORE` boundary",
            "executable custody, and typed recovery evidence",
            "Process evidence protects ownership and closure",
            "Timestamp, link-count, and unrelated child-entry churn",
            "explicit result-owner contract implemented by the real",
            "only the caller settles the",
            "closure recovery owner then holds the exact lease",
            "`CustodiedManifestResultOwner.retained` becomes true only after",
            "protects descriptor object identity and close",
            "different reused object",
            "never retries the close",
        ):
            self.assertIn(contract, helper_contract)
        for contract in (
            'platform.machine() != "arm64"',
            "_matches_hosted_fail_closed_observations(evidence)",
            "blockers == expected_blockers",
            "len(blockers) == len(evidence.blockers)",
            '"reviewed_fail_closed_signature": signature_matches',
            "if evidence.compatible or evidence.production_capable",
        ):
            self.assertIn(contract, hosted_probe)
        self.assertNotIn("sandbox_apply", hosted_probe)
        for requirement in (
            "operator-enforced exact-head gate",
            "nine tests run, zero skips",
            "Any push invalidates that evidence",
            "Hosted CI's blocker-signature probe is not a substitute",
            "cd skills/review-orchestration-playbook/scripts/"
            "independent_codex_pr_review",
            "TRUSTED_PYTHON=/absolute/path/to/parent-validated/python3.13",
            '"$TRUSTED_PYTHON" -B -m tests.run_required_no_child_profile',
            "no-group-write/no-other-write",
            "interpreter's absolute path and digest",
            "tests.run_required_no_child_profile",
        ):
            self.assertIn(requirement, pr_readiness)
        integration_test = (
            SCRIPTS / "independent_codex_pr_review/tests/test_no_child_profile.py"
        ).read_text(encoding="utf-8")
        production_profile = (
            SCRIPTS
            / "independent_codex_pr_review/review_supervisor/no_child_profile.py"
        ).read_text(encoding="utf-8")
        hosted_profile = "github-macos-26-arm64-26.4-25E246"
        self.assertIn(hosted_profile, integration_test)
        self.assertNotIn(hosted_profile, production_profile)
        self.assertNotIn("25E246", production_profile)

        profile_contracts = {
            "canonical": (
                "test",
                "skills/review-orchestration-playbook",
            ),
            "private": (
                "python-39-compatibility",
                "personal_codex/skills/review-orchestration-playbook",
            ),
        }
        for profile, (next_job, skill_root) in profile_contracts.items():
            workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(encoding="utf-8")
            start = workflow.index("  independent_supervisor_tests:")
            end = workflow.index(f"\n  {next_job}:", start)
            supervisor_job = workflow[start:end]
            with self.subTest(profile=profile):
                self.assertIn("runs-on: macos-26", supervisor_job)
                self.assertIn("timeout-minutes: 15", supervisor_job)
                self.assertIn(
                    """      - name: Report hosted no-child runtime fingerprint
        run: |
          /usr/bin/sw_vers -productVersion
          /usr/bin/sw_vers -buildVersion
          /usr/bin/uname -r
          /usr/bin/uname -m
          /usr/bin/shasum -a 256 /usr/bin/sandbox-exec
""",
                    supervisor_job,
                )
                self.assertIn(
                    f"""      - name: Match hosted no-child blocker signature
        working-directory: {skill_root}/scripts/independent_codex_pr_review
        env:
          CODEX_REVIEW_LIVE_NO_CHILD_RUNTIME_PROFILE: github-macos-26-arm64-26.4-25E246
          CODEX_REVIEW_RUNNER_ENVIRONMENT: ${{{{ runner.environment }}}}
          CODEX_REVIEW_RUNNER_ARCH: ${{{{ runner.arch }}}}
        run: |
          python3 -m tests.run_hosted_no_child_fail_closed
      - name: Run deterministic independent supervisor tests
        working-directory: {skill_root}/scripts/independent_codex_pr_review
        run: |
          python3 -m tests.run_required_deterministic_supervisor
""",
                    supervisor_job,
                )
                self.assertIn(
                    f"""      - name: Verify installed release tree remains immutable
        working-directory: {skill_root}/tests
        run: |
          python3 -m unittest -v test_contracts.RepositoryContractTest.test_installed_supervisor_preflight_keeps_release_tree_immutable
""",
                    supervisor_job,
                )
                self.assertNotIn("tests.run_required_no_child_profile", supervisor_job)
                self.assertNotIn(
                    "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE",
                    supervisor_job,
                )

    def test_independent_supervisor_remains_a_bounded_low_level_tool(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        entrypoint = tool_root / "independent-codex-pr-review"
        readme = (tool_root / "README.md").read_text(encoding="utf-8")
        constants = (tool_root / "review_supervisor/constants.py").read_text(
            encoding="utf-8"
        )
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

        self.assertTrue(entrypoint.is_file())
        self.assertTrue(entrypoint.stat().st_mode & 0o111)
        self.assertEqual(
            entrypoint.read_text(encoding="utf-8").splitlines()[0],
            "#!/usr/bin/env python3.13",
        )
        self.assertIn('MODEL = "gpt-5.6-sol"', constants)
        self.assertIn('REASONING_EFFORT = "xhigh"', constants)
        self.assertIn("MAX_EVIDENCE_BUNDLE_BYTES", constants)
        for anchor in (
            "owner-only `CODEX_HOME`",
            "bounded evidence bundle",
            "app-server",
            "sealed",
            "settlement",
        ):
            self.assertIn(anchor, readme)
        self.assertIn("independent_supervisor_tests", workflow)
        self.assertIn('python-version: "3.13"', workflow)
        self.assertIn(
            "scripts/independent_codex_pr_review",
            workflow,
        )

    def test_helper_declares_and_tests_its_minimum_python_runtime(self) -> None:
        entrypoint = (SCRIPTS / "isolated_review").read_text(encoding="utf-8")
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        guard = "if sys.version_info < (3, 10):"
        self.assertIn(guard, entrypoint)
        self.assertLess(
            entrypoint.index(guard), entrypoint.index("from review_runtime")
        )
        self.assertIn('python-version: "3.10"', workflow)
        self.assertIn("tomli==2.2.1", workflow)
        self.assertIn("requires Python 3.10 or later", readme)

    def test_helper_entrypoint_does_not_write_import_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            copied_scripts = pathlib.Path(temp_dir) / "scripts"
            shutil.copytree(
                SCRIPTS,
                copied_scripts,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)

            completed = subprocess.run(
                (str(copied_scripts / "isolated_review"), "--help"),
                cwd=copied_scripts,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            bytecode_artifacts = sorted(
                path.relative_to(copied_scripts).as_posix()
                for path in copied_scripts.rglob("*")
                if path.name == "__pycache__" or path.suffix == ".pyc"
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(bytecode_artifacts, [])

    def test_core_policy_defines_progressive_provider_strict_review_shapes(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        for anchor in (
            "Single / single review / single internal review | One fresh-context Codex reviewer.",
            "Double / double review / local double review | Single plus one actual Claude Code reviewer.",
            "Triple / triple review | Double plus exact `@codex review` on an exact-host `github.com` PR",
            "Each logical lane receives its own workspace",
            "intentional review-anchor commit",
            "Materialize a separate lane-private Git workspace at `head_sha`",
            "Enforce read-only reviewer behavior",
            '`fork_turns="none"`',
            "review-control metadata",
            "independently trusted bundle pinned outside",
            "exact authoritative playbook path/version in the prompt",
            "Both local lanes follow the same discovery order",
            "path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks",
            "Codex must load exactly the parent-named authoritative source",
            "Do not prepare, paste, attach, or point either reviewer to a full diff",
            "Do not use its Codex path to satisfy single review",
            "actual Claude Code process in a second independently materialized clean Git workspace",
            "A Copilot, Cursor, OpenCode, or other model-family result does not satisfy the Claude Code lane",
        ):
            self.assertIn(anchor, skill)

        for anchor in (
            "pre-status isolated reachable-object import",
            "Never derive a formal named-lane range from a dirty working tree",
            "Expose the workspace and Git metadata for read-only reviewer behavior",
            "free of generated prompts, diff files, manifests, state directories, and helper control artifacts",
            "The reviewer prompt contains only review-control metadata:",
            "instruction-loading order, read-only and evidence limits",
            "for both local lanes, the same discovery order",
            "path-scoped `AGENTS.md`, repo-local domain skills, tracked project guidance, then hunks",
            "exact authoritative playbook path/version selected by the parent",
            "independently trusted external bundle pinned outside the candidate range",
            "compute or persist a reviewer-visible full diff",
            '`fork_turns="none"`',
            "Use an actual Claude Code process in a second lane-unique clean Git worktree",
            "A different provider cannot satisfy this lane",
        ):
            self.assertIn(anchor, contracts)

    def test_skill_interface_distinguishes_direct_and_helper_authentication(
        self,
    ) -> None:
        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")

        for anchor in (
            "manifest-bound named_lane_guard validate-claude-stream profile",
            "named-direct lane accepts only ordinary local login in real HOME",
            "low-level helper selects authentication with precedence "
            "ANTHROPIC_API_KEY > CLAUDE_CODE_OAUTH_TOKEN > local login",
            "helper local login uses its private credential carrier/broker and "
            "guarded writeback",
            "helper API-key/OAuth modes bypass that transaction",
        ):
            self.assertIn(anchor, interface)
        self.assertNotIn(
            "require validate_claude_stream.py classification accepted",
            interface,
        )

    def test_report_only_review_never_implicitly_authorizes_an_anchor_commit(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        causal_anchors = [
            (
                skill,
                "When the intended review scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization`",
            ),
            (
                contracts,
                "when its intended scope includes dirty or untracked state that no committed range represents, report review preparation as `blocked-authorization`",
            ),
            (
                readiness,
                "implementation checkout is dirty and no committed review range exists, report review preparation as `blocked-authorization`",
            ),
            (
                agents_policy,
                "Reserve `blocked-authorization` for intended dirty/untracked state that would require an unauthorized anchor commit",
            ),
            (
                interface,
                "intended dirty/untracked state without a representing committed range is blocked-authorization",
            ),
        ]
        if CI_PROFILE == "canonical":
            readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
            causal_anchors.append(
                (
                    readme,
                    "Use `blocked-authorization` when the intended scope includes dirty or untracked state that would require an unauthorized anchor commit",
                )
            )
        for document, anchor in causal_anchors:
            with self.subTest(anchor=anchor):
                self.assertIn(anchor, document)

        active_documents = [skill, contracts, readiness, agents_policy, interface]
        if CI_PROFILE == "canonical":
            active_documents.append(readme)
        for document in active_documents:
            self.assertNotIn(
                "If implementation changes are uncommitted, create an intentional review-anchor commit",
                document,
            )

    def test_github_codex_fallback_and_pr_readiness_preserve_the_shape(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")

        for anchor in (
            "only a proven missing PR, unsupported host, or unsupported operating identity establishes third-lane unavailability",
            "sqbu-github.cisco.com",
            "operating identity is in `{hoteng, hoteng_cisco}`",
            "Report `requested: triple`, `effective: double`, and the concrete reason",
            "exact `@codex review`",
        ):
            self.assertIn(anchor, skill)
        for anchor in (
            "It never adds a hidden local Codex review",
            "Each reviewer gets that lane-unique read-only worktree and clear control metadata",
            "never prepare or inject a full diff",
            "Persist `requested: triple`, `effective: double`, and a concrete reason",
            "exact `@codex review` comment",
            "effective: triple-inconclusive",
        ):
            self.assertIn(anchor, readiness)
        self.assertIn(
            "GitHub Codex unavailability changes only triple to effective double",
            contracts,
        )
        self.assertIn("effective: triple-inconclusive", contracts)
        self.assertIn(
            "with GitHub lane status `blocked-authorization`",
            contracts,
        )
        exact_head_documents = (agents_policy, skill, contracts, templates)
        for document in exact_head_documents:
            self.assertIn("`headRefOid` does not equal", document)
        self.assertIn("`headRefOid != head_sha`", probes)
        for document in (*exact_head_documents, probes):
            self.assertIn("blocked-authorization", document)
            self.assertNotIn("does not contain the frozen head", document)
            self.assertNotIn("does not contain the intended frozen head", document)
        intended_range_anchor = "Preserve any parent-provided frozen `base_sha..head_sha` as the intended range"
        separate_pr_head_anchor = "record the current `headRefOid` separately as `pr_head_oid`; never overwrite the intended `head_sha` with it"
        compare_anchor = "Compare `pr_head_oid` with the intended `head_sha` before running local lanes or reading PR CI, conversation, ruleset, mergeability, or other readiness state"
        run_lanes_anchor = "Run the requested local lanes"
        classify_anchor = "make only the pre-request classifications that available evidence can prove"
        eligible_anchor = (
            "Unknown pre-request integration/service status does not block the request"
        )
        for anchor in (
            intended_range_anchor,
            separate_pr_head_anchor,
            compare_anchor,
            classify_anchor,
            eligible_anchor,
        ):
            self.assertIn(anchor, readiness)
        self.assertLess(
            readiness.index(intended_range_anchor), readiness.index(compare_anchor)
        )
        self.assertLess(
            readiness.index(separate_pr_head_anchor), readiness.index(compare_anchor)
        )
        self.assertLess(
            readiness.index(compare_anchor), readiness.index(run_lanes_anchor)
        )
        read_readiness_anchor = (
            "Read required CI/check state and unresolved PR conversations"
        )
        self.assertLess(
            readiness.index(compare_anchor), readiness.index(read_readiness_anchor)
        )
        self.assertLess(
            readiness.index(run_lanes_anchor), readiness.index(classify_anchor)
        )
        for scenario in (
            "a selected PR in single, double, triple, and triple already reduced to effective double",
            "No comparison exists for explicit-range-only standalone single/double with no selected PR",
            "Only authenticated actual PR absence takes the no-PR path",
            "existing PR on an unsupported host or identity remains on the existing-PR path",
            "The fixed authority baseline has no accepted no-start body grammar",
            "Posting the request is not service start",
            "nonterminal/check-only",
        ):
            self.assertIn(scenario, readiness)
        self.assertNotIn(
            "Only for an existing supported third-lane candidate",
            readiness,
        )
        self.assertNotIn(
            "Supported: a GitHub Cloud PR where the Codex review integration is available",
            readiness,
        )
        self.assertIn(
            "do not require PR-only fields when no PR was selected", readiness
        )
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            contracts,
        )
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            readiness,
        )
        self.assertIn(
            "any operating identity in `{hoteng, hoteng_cisco}`",
            probes,
        )
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", contracts)
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", readiness)
        self.assertNotIn("on Cisco GitHub Enterprise Cloud", probes)
        self.assertIn(
            "Proved no PR or directly unsupported host/identity means effective double",
            interface,
        )
        self.assertIn(
            "A missing response, otherwise valid nonterminal/check-only evidence, "
            "or a retryable transport/read failure remains pending while bounded "
            "waiting is meaningful",
            interface,
        )
        self.assertIn(
            "Unknown provider identity, malformed/stale evidence, a non-retryable "
            "failure, or an unstable final read is immediately triple-inconclusive",
            interface,
        )

    def test_github_codex_provider_evidence_authority_converges_duplicates(
        self,
    ) -> None:
        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        normalized = " ".join(authority.split()).lower()

        scenario_outcomes = {
            "R1-clean1-R2-pending": "clean",
            "R1-clean1-R2-clean2": "clean",
            "R1-R2-clean1-clean2": "clean",
            "R1-clean1-R2-findings2": "findings",
        }
        for scenario, expected_outcome in scenario_outcomes.items():
            matching_lines = [
                line.lower()
                for line in authority.splitlines()
                if scenario.lower() in line.lower()
            ]
            with self.subTest(scenario=scenario):
                self.assertTrue(matching_lines, f"missing scenario {scenario}")
                self.assertTrue(
                    any(
                        expected_outcome
                        in {cell.strip().strip("`") for cell in line.split("|")}
                        for line in matching_lines
                    ),
                    f"{scenario} must have an exact {expected_outcome} outcome cell",
                )

        unquoted = normalized.replace("`", "")
        for anchor in (
            "duplicate-observed is warning-only",
            "does not require request/run attribution",
            "latest trustworthy terminal artifact",
            "if an accepted request already exists, it does not post another one",
            "a lone request that was posted under producer policy and is still pending",
            "compliant, not a warning",
            "does not independently invalidate complete provider-result evidence",
            "base-changed-same-head",
        ):
            self.assertIn(anchor.lower(), unquoted)
        self.assertIn("request_policy.status: warning", skill)
        self.assertIn("request_policy.warnings", skill)
        self.assertNotIn("request_policy: duplicate-observed", skill)

    def test_github_codex_provider_evidence_authority_is_fail_closed(
        self,
    ) -> None:
        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(authority.split()).lower()

        for anchor in (
            "unresolved thread finding",
            (
                "a newer or equal-time malformed or scope-conflicting "
                "terminal-looking artifact blocks an older clean result"
            ),
            "pagination",
            "aggregate issue-comment reaction counts do not identify the actor",
            "fully paginated individual reaction records",
            "fixed grammar below and an exact commit binding",
            "state admissibility and terminal-looking detection are separate",
            "`dismissed` is terminal-looking but inadmissible",
            (
                "a missing or unknown state is terminal-looking when the "
                "normalized review body is nonempty"
            ),
            "whole-snapshot inconclusive blocker",
            "original `submitted_at` cannot make it older than",
            "do not let a later-looking clean supersede them",
            "an empty `approved` review is not clean",
            "stable numeric artifact id",
            "any trustworthy finding in the set takes precedence over every clean",
            "incompatible artifacts without another provider-stable ordering signal are ambiguous",
            "any malformed or scope-conflicting member of that equal-time set",
            "scope",
            "final re-read",
            "same or successor head",
            (
                "a top-level finding may be superseded by a later clean artifact "
                "on the same or successor head"
            ),
            "an unresolved thread finding is not superseded",
        ):
            self.assertIn(anchor, normalized)

        for profile in (
            "terminal-payload",
            "mixed",
            "thumbs-up-clean",
            "unknown",
        ):
            self.assertIn(f"`{profile}`", authority)

        profile_expectations = {
            "terminal-payload": ("reactions are not clean evidence",),
            "thumbs-up-clean": (
                "explicitly defined `+1` as completed-clean",
                "reaction-only operation",
            ),
            "unknown": ("reaction-only outcome remains pending or inconclusive",),
        }
        for profile, expected_phrases in profile_expectations.items():
            profile_lines = [
                line.lower()
                for line in authority.splitlines()
                if line.lower().startswith(f"| `{profile}` |")
            ]
            with self.subTest(provider_profile=profile):
                self.assertEqual(len(profile_lines), 1)
                for phrase in expected_phrases:
                    self.assertIn(phrase, profile_lines[0])

        for anchor in (
            "+1 fallback requires all of the following",
            "provider_profile is thumbs-up-clean",
            "an exact +1",
            "exact accepted request comment",
            "exact provider identity",
            "created strictly after the request's semantic server time",
            "complete pagination",
            "stable current scope",
            (
                "complete same-repository historical candidate universe for the "
                "last 30 days"
            ),
            "historical candidates exclude the exact current scope",
            "current outcome is validated separately",
            "never counts toward the three-outcome history minimum",
            "select exactly the first 10 candidates when 10 or more exist",
            "never skip an incomplete, conflicting, or unfavourable candidate",
            "fewer than 3 distinct selected reaction-only outcomes yields unknown",
            "the three-outcome minimum applies only to selecting reaction-only",
            "observed behaviour” means behaviour in the deterministic selected outcome window",
            "its payload kind does not itself select the provider profile",
            "at most one final candidate outcome per distinct immutable scope key",
            "frozen whole-pr base_sha equal to pr_merge_base",
            "never use the moving baserefoid as this key",
            (
                "base-branch advancement that leaves pr_merge_base and head unchanged "
                "is still one outcome"
            ),
            (
                "duplicate requests, duplicate reactions, and multiple artifacts for "
                "one scope never increase the sample size"
            ),
            "every selected candidate must have exact provider identity",
            "stable recorded scope",
            "normalized body is exactly `@codex review`",
            "record each request's id, url, `created_at`, `updated_at`, normalized body, and scope",
            "record every reaction's id, canonical reaction-resource api url",
            "`parent_request_id`",
            "`issues/comments/<parent_request_id>/reactions?per_page=100` fetch url",
            "`created_at`, content, login, and type",
            "`reaction.created_at > request.request_server_time`",
            "a reaction that predates an edit into `@codex review`",
            "`request_server_time_field: created_at | updated_at`",
            "de-duplicate only repeated api records with the same positive reaction id",
            "any exact-provider reaction on any same-scope parent with other content",
            "an `eyes` at or after the selected `+1`",
            "aggregate reaction counts and a single selected parent's reaction page "
            "cannot prove the absence of a cross-parent conflict",
            "provider-explicit `+1` semantics",
            "only active declaration authority is an exact provider-authored "
            "github issue-comment artifact",
            "fetched directly from its canonical rest resource",
            "generic `issuer`/`source` strings",
            "a local paraphrase with a self-consistent hash",
            "caller-supplied fields alone never authenticate it",
            "trusted github rest response `date` header",
            "`window_seconds: 2592000`",
            "`window_start_exclusive = as_of_server_time - 2592000",
            "a candidate basis at the lower boundary is outside the window",
            "candidate_universe_count",
            "including candidates that will fall outside the selected 10-outcome "
            "window",
            "a later `eyes`",
            "sha-256 of its normalized content",
            "`normalization: crlf-and-cr-to-lf+utf8`",
            "every selected history entry records its immutable scope",
            "strict request-semantic-time-before-reaction ordering",
            "no trustworthy current-scope terminal artifact",
            "no current-scope terminal-looking malformed artifact",
            (
                "no active top-level finding on the current head or a proved ancestor "
                "head"
            ),
            "reaction-only clean never supersedes a finding",
            "no unresolved thread finding",
            "no cross-parent conflict under the rule above",
            "every accepted current-scope controlled request",
            "no cross-parent conflict",
            "selected +1 is later than every such request",
            "single selected parent's reaction page cannot prove",
            "same_scope_request_audit",
            ("every one reaction-only and none containing a clean terminal payload"),
            "final re-read is unchanged",
            "`eyes` is liveness-only",
            "if any condition is absent",
            (
                "the only clean-completion path that deliberately has no terminal "
                "review/comment payload"
            ),
        ):
            self.assertIn(
                anchor.lower().replace("`", ""),
                normalized.replace("`", ""),
            )
        self.assertIn(
            "`eyes` is liveness-only: it can show that work started or "
            "restarted, but it never proves clean",
            normalized,
        )
        for anchor in (
            "fixed terminal-payload grammar",
            'performed_via_github_app.slug == "chatgpt-codex-connector"',
            "codex review: didn't find any major issues.[ optional_tagline]",
            "**reviewed commit:** `<full_40_hex_sha>`",
            'rest `state == "approved"`',
            "normalized body exactly equal to `no findings.`",
            "ascii rfc 3986 absolute uri",
            "https://github.com/<exact_owner>/<exact_repo>/blob/"
            "<full_40_hex_sha>/<path>#l<positive_line>",
            "native full-sha `commit_id` to equal that sha",
            "inline-parent review container",
            "no reviewed-commit marker is present or required",
            "`pull_request_review_id` equal to the parent review id",
            "`original_commit_id == p`",
            "all other terminal-looking exact-provider comments or reviews "
            "are malformed",
            "a 10-character sha",
            "`no findings!`",
            "an empty `approved` review",
            "`looks good.`",
            "a short-sha or cross-repository finding url",
            "positive example for each active grammar branch",
            "**reviewed commit:** `0123456789abcdef0123456789abcdef01234567`",
            "commit_id: 0123456789abcdef0123456789abcdef01234567",
            "body: no findings.",
            "pull_request_review_id: 123456789",
            "original_commit_id: 0123456789abcdef0123456789abcdef01234567",
            "https://github.com/owner/repo/blob/"
            "0123456789abcdef0123456789abcdef01234567/"
            "path/to/file.py#l10",
            "the contract fixture matrix is normative",
            "exercise every row against a closed reference classifier",
        ):
            self.assertIn(anchor, normalized)
        self.assertIn(
            "every ordered historical request/reaction sample",
            normalized,
        )

        mixed_profile_lines = [
            line.lower()
            for line in authority.splitlines()
            if line.lower().startswith("| `mixed` |")
        ]
        self.assertEqual(len(mixed_profile_lines), 1)
        self.assertIn(
            "terminal payload remains the only clean authority",
            mixed_profile_lines[0],
        )
        self.assertIn(
            "reaction-only evidence cannot independently pass",
            mixed_profile_lines[0],
        )

        for anchor in (
            "`provider_profile` is recomputed from the final complete snapshot",
            "not a sticky provider preference",
            "`+1` cannot independently establish clean in this profile",
        ):
            self.assertIn(anchor.lower(), normalized)

        for field in (
            "request_policy",
            "provider_profile",
            "evidence_basis",
        ):
            self.assertIn(field, authority)

        self.assertIn(
            "16366aa81270ad2c875d2ceb8ce194f5b2308af6",
            authority,
        )
        self.assertIn(
            "2a7f9d8cd98f90cb56dc1540bf54d9dc7484afc6",
            authority,
        )

        baseline_manifest = {
            "COOKBOOK.md": "70784aed0869504d85cd9b95710b2dea427841e5",
            "COOKBOOK.zh-CN.md": "f7dc955b8ebd1673883d38352f37b58099b1227d",
            "DESIGN.md": "8de87334a37bd85a6b3f3d1a4362933eeacbab25",
            "DESIGN.zh-CN.md": "45026f208847f1385780ffe9904b58b98903fb44",
            "EULA.md": "eeaeb240bb31e35e2d7c574c044d3ddcbb64ea30",
            "LICENSE": "d9a10c0d8e868ebf8da0b3dc95bb0be634c34bfe",
            "README.md": "c43aeded90def8d5876dec6d67e07a7cdcfac038",
            "README.zh-CN.md": "c66a93b90a3354269f2f91135103490cc949a81e",
            "SECURITY.md": "ae8b45461e2f41350b1e6fc7343504fc4c9dcd8b",
            "SUPPORT.md": "4378a1e3377ee0fb58fcaa7a2ad715a4d53e814f",
            "action.yml": "2169ca33d1cb8c698805513768e6a5c34887fe35",
            "package.json": "b554018df447543590a0f732968892ccc22050f3",
            "src/core.mjs": "7270586bced68f0faca15ebe844f0517dc7b1ec3",
            "src/evidence-budget.mjs": "b2a07e9a4dd33dc60d138d97a59444b3fc537677",
            "src/gate.mjs": "e0b974b27ebd64e412eaef1d069789b5f6bd76ba",
        }
        self.assertEqual(len(baseline_manifest), 15)
        self.assertIn(
            "d03de9035d20f285e6a93986d436403b4a30e9bc",
            authority,
        )
        for relative_path, blob_id in baseline_manifest.items():
            with self.subTest(action_baseline_path=relative_path):
                self.assertIn(
                    f"| `{relative_path}` | `{blob_id}` |",
                    authority,
                )

        for rationale in (
            "a provider-authored terminal payload carries the actual "
            "finding/no-findings decision and commit scope",
            "github review and issue-comment apis do not expose a general "
            "request/run lineage",
            "duplicate or mistimed requests are still actionable orchestration "
            "defects, but they do not contradict what the provider reported",
        ):
            self.assertIn(rationale, normalized)
        for upstream_regression in (
            "valid current-head clean passes without creating a review marker",
            "current-head clean passes regardless of marker timing or deadline",
            "clean predates active marker",
            "marker and audit history cannot reject stable current-head clean",
            "conflicting trusted markers",
        ):
            self.assertIn(upstream_regression, normalized)

        for anchor in (
            "complete 15-file release tree",
            "complete `packages/action/` tree",
            "`src/core.mjs`",
            "`src/evidence-budget.mjs`",
            "alignment and intentional differences from the fixed action baseline",
            "duplicate result consumption aligns with the action",
            "early-result consumption aligns with the action",
            "warning codes are a playbook extension",
            "local-lane sequencing is a playbook extension",
            "whole-pr scope and lifecycle are stricter",
            "an empty `approved` review is not clean",
            "the `+1` fallback is new playbook policy",
            "`eyes` remains orchestration-only",
            "duplicate result consumption aligns with the action",
            "early-result consumption aligns with the action",
        ):
            self.assertIn(anchor, normalized)

        for anchor in (
            "fixed authority baseline intentionally defines no accepted no-start body grammar",
            "free-form prose that appears to say",
            "provider-backed declaration",
            "evidence_basis.kind: no-start-rejection",
            "actually recomputed `provider_profile`",
            "server_time_field: submitted_at",
            "server_time_field: created_at",
            "server_time_field: updated_at",
            "proved pre-provider ineligibility or blocker",
            "eligible and waiting with no selected provider artifact",
            "accepted weak reaction clean",
            "future accepted authenticated no-start rejection",
        ):
            self.assertIn(anchor, normalized)

    def test_github_codex_terminal_grammar_fixture_matrix(self) -> None:
        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        current_sha = "0123456789abcdef0123456789abcdef01234567"
        other_sha = "fedcba9876543210fedcba9876543210fedcba98"
        review_id = 123456789
        disclosure = "\n".join(
            (
                "<details> <summary>ℹ️ About Codex in GitHub</summary>",
                "<br/>",
                "Codex has been enabled to automatically review pull requests in this repo. Reviews are triggered when you",
                "- Open a pull request for review",
                "- Mark a draft as ready",
                '- Comment "@codex review".',
                "If Codex has suggestions, it will comment; otherwise it will react with 👍.",
                'When you [sign up for Codex through ChatGPT](https://openai.com/codex), Codex can also answer questions or update the PR, like "@codex address that feedback".',
                "</details>",
            )
        )
        eligible_finding_commits = {current_sha, other_sha}

        def inline_container(commit_id: str) -> str:
            return "\n".join(
                (
                    "### 💡 Codex Review",
                    "Here are some automated review suggestions for this pull request.",
                    f"**Reviewed commit:** `{commit_id}`",
                    "",
                    disclosure,
                )
            )

        def clone(value: dict[str, object]) -> dict[str, object]:
            return json.loads(json.dumps(value))

        def normalize_body(value: object) -> str | None:
            if not isinstance(value, str):
                return None
            normalized = (
                value.replace("\r\n", "\n")
                .replace("\r", "\n")
                .replace("\v", "\n")
                .replace("\f", "\n")
                .replace("\u0085", "\n")
                .replace("\u2028", "\n")
                .replace("\u2029", "\n")
            )
            if any(
                codepoint == 0
                or (
                    (codepoint < 0x20 or 0x7F <= codepoint <= 0x9F)
                    and codepoint not in (0x09, 0x0A)
                )
                for codepoint in map(ord, normalized)
            ):
                return None
            return normalized.strip("\t\n ")

        finding_line = re.compile(
            r"^- \[P[0-3]\] (?P<title>.{1,240}) — "
            r"https://github\.com/OWNER/REPO/blob/"
            r"(?P<sha>[0-9a-f]{40})/"
            r"(?P<path>(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]|%[0-9A-F]{2})+)"
            r"#L[1-9][0-9]*(?:-L[1-9][0-9]*)?$"
        )

        def finding_sha(body: str) -> str | None:
            lines = body.split("\n")
            if len(lines) < 2 or lines[0] != "### 💡 Codex Review":
                return None
            shas: set[str] = set()
            for line in lines[1:]:
                match = finding_line.fullmatch(line)
                if match is None:
                    return None
                title = match.group("title")
                path = match.group("path")
                try:
                    decoded_path = urllib.parse.unquote_to_bytes(path).decode(
                        "utf-8", errors="strict"
                    )
                except UnicodeDecodeError:
                    return None
                if (
                    title != title.strip("\t ")
                    or " — " in title
                    or any(unicodedata.category(char) == "Cc" for char in title)
                    or any(
                        segment in ("", ".", "..")
                        for segment in decoded_path.split("/")
                    )
                ):
                    return None
                shas.add(match.group("sha"))
            return next(iter(shas)) if len(shas) == 1 else None

        def exact_provider(record: dict[str, object]) -> bool:
            return (
                record.get("user_login") == "chatgpt-codex-connector[bot]"
                and record.get("user_type") == "Bot"
            )

        def exact_inline_child(
            record: object,
            *,
            parent_id: int,
            commit_id: str,
        ) -> bool:
            if not isinstance(record, dict):
                return False
            child_id = record.get("id")
            body = normalize_body(record.get("body"))
            expected_keys = {
                "id",
                "url",
                "user_login",
                "user_type",
                "pull_request_review_id",
                "commit_id",
                "original_commit_id",
                "body",
                "normalized_body",
                "thread_id",
                "thread_resolved",
            }
            return (
                set(record) == expected_keys
                and type(child_id) is int
                and child_id > 0
                and record.get("url")
                == (f"https://github.com/OWNER/REPO/pull/1#discussion_r{child_id}")
                and exact_provider(record)
                and type(record.get("pull_request_review_id")) is int
                and record.get("pull_request_review_id") == parent_id
                and record.get("commit_id") == commit_id
                and record.get("original_commit_id") == commit_id
                and bool(body)
                and record.get("normalized_body") == body
                and record.get("thread_id") == f"PRRT_{child_id}"
                and type(record.get("thread_resolved")) is bool
            )

        def classify(record: dict[str, object]) -> str:
            if not exact_provider(record):
                return "malformed"
            channel = record.get("channel")
            state = record.get("state")
            if channel == "review" and state == "PENDING":
                return "nonterminal"
            body = normalize_body(record.get("body"))
            if body is None:
                return "malformed"
            if channel == "issue-comment":
                if (
                    record.get("app_slug") == "chatgpt-codex-connector"
                    and body.count("**Reviewed commit:**") == 1
                ):
                    short_taglines = {
                        "",
                        " :rocket:",
                        " :tada:",
                        " :+1:",
                        " 🚀",
                        " 🎉",
                        " 👍",
                        " ✨",
                        " ✅",
                    }
                    stems = {
                        "Nice work",
                        "Chef's kiss",
                        "What shall we delve into next",
                        "Already looking forward to the next diff",
                        "Keep them coming",
                        "Swish",
                        "Another round soon, please",
                        "Breezy",
                        "Can't wait for the next one",
                        "More of your lovely PRs please",
                        "Bravo",
                        "Keep it up",
                        "Delightful",
                        "Hooray",
                        "You're on a roll",
                    }
                    taglines = short_taglines | {
                        f" {stem}{punctuation}"
                        for stem in stems
                        for punctuation in (".", "!", "?")
                    }
                    clean_lead = "Codex Review: Didn't find any major issues."
                    marker = f"**Reviewed commit:** `{current_sha}`"
                    for tagline in taglines:
                        core = f"{clean_lead}{tagline}\n\n{marker}"
                        if body in (core, f"{core}\n\n{disclosure}"):
                            return "clean"
                return "findings" if finding_sha(body) is not None else "malformed"
            if channel != "review":
                return "malformed"
            children = record.get("children")
            if state == "DISMISSED":
                return "malformed"
            if state not in ("APPROVED", "COMMENTED", "CHANGES_REQUESTED"):
                return (
                    "malformed"
                    if body or (isinstance(children, list) and bool(children))
                    else "nonterminal"
                )
            commit_id = record.get("commit_id")
            parent_id = record.get("id")
            if type(parent_id) is not int or parent_id <= 0:
                return "malformed"
            if state == "APPROVED":
                if (
                    commit_id != current_sha
                    or body != "No findings."
                    or not isinstance(children, list)
                ):
                    return "malformed"
                child_ids: set[int] = set()
                for child_record in children:
                    if (
                        not exact_inline_child(
                            child_record,
                            parent_id=parent_id,
                            commit_id=commit_id,
                        )
                        or child_record["id"] in child_ids
                    ):
                        return "malformed"
                    child_ids.add(child_record["id"])
                return "findings" if children else "clean"
            found_sha = finding_sha(body)
            if found_sha is not None:
                return (
                    "findings"
                    if state in ("COMMENTED", "CHANGES_REQUESTED")
                    and commit_id == found_sha
                    else "malformed"
                )
            if (
                state != "COMMENTED"
                or commit_id not in eligible_finding_commits
                or body not in ("", inline_container(str(commit_id)))
                or not isinstance(children, list)
                or not children
            ):
                return "malformed"
            child_ids = set()
            for child in children:
                if (
                    not exact_inline_child(
                        child,
                        parent_id=parent_id,
                        commit_id=commit_id,
                    )
                    or child["id"] in child_ids
                ):
                    return "malformed"
                child_ids.add(child["id"])
            return "findings"

        clean_issue = {
            "channel": "issue-comment",
            "user_login": "chatgpt-codex-connector[bot]",
            "user_type": "Bot",
            "app_slug": "chatgpt-codex-connector",
            "body": (
                "Codex Review: Didn't find any major issues.\n\n"
                f"**Reviewed commit:** `{current_sha}`"
            ),
        }
        clean_review = {
            "channel": "review",
            "id": review_id,
            "user_login": "chatgpt-codex-connector[bot]",
            "user_type": "Bot",
            "state": "APPROVED",
            "commit_id": current_sha,
            "body": "No findings.",
            "children": [],
        }
        finding = {
            "channel": "issue-comment",
            "user_login": "chatgpt-codex-connector[bot]",
            "user_type": "Bot",
            "app_slug": "chatgpt-codex-connector",
            "body": (
                "### 💡 Codex Review\n"
                "- [P1] Example finding — "
                "https://github.com/OWNER/REPO/blob/"
                f"{current_sha}/path/to/file.py#L10"
            ),
        }
        child = {
            "id": 987654321,
            "url": "https://github.com/OWNER/REPO/pull/1#discussion_r987654321",
            "user_login": "chatgpt-codex-connector[bot]",
            "user_type": "Bot",
            "pull_request_review_id": review_id,
            "commit_id": current_sha,
            "original_commit_id": current_sha,
            "body": "[P1] Example inline finding",
            "normalized_body": "[P1] Example inline finding",
            "thread_id": "PRRT_987654321",
            "thread_resolved": False,
        }
        inline_parent = {
            "channel": "review",
            "id": review_id,
            "user_login": "chatgpt-codex-connector[bot]",
            "user_type": "Bot",
            "state": "COMMENTED",
            "commit_id": current_sha,
            "body": "",
            "children": [child],
        }

        fixtures: list[tuple[str, str, str, str, dict[str, object]]] = []

        def add(
            name: str,
            branch: str,
            mutation: str,
            expected: str,
            record: dict[str, object],
        ) -> None:
            fixtures.append((name, branch, mutation, expected, record))

        add("clean-issue-positive", "clean issue comment", "none", "clean", clean_issue)
        add(
            "clean-review-positive",
            "clean pull-request review",
            "none",
            "clean",
            clean_review,
        )
        approved_with_inline_finding = clone(clean_review)
        approved_with_inline_finding["children"] = [child]
        add(
            "clean-review-with-inline-finding",
            "clean pull-request review",
            "associated inline finding",
            "findings",
            approved_with_inline_finding,
        )
        clean_review_without_children = clone(clean_review)
        clean_review_without_children.pop("children")
        add(
            "clean-review-unread-children",
            "clean pull-request review",
            "associated inline set unavailable",
            "malformed",
            clean_review_without_children,
        )
        add("finding-positive", "top-level finding", "none", "findings", finding)
        add(
            "inline-parent-positive",
            "inline-parent review",
            "none",
            "findings",
            inline_parent,
        )
        nonempty_parent = clone(inline_parent)
        nonempty_parent["body"] = inline_container(current_sha)
        add(
            "inline-parent-nonempty-positive",
            "inline-parent review",
            "exact container body and disclosure",
            "findings",
            nonempty_parent,
        )
        short_sha = clone(clean_issue)
        short_sha["body"] = str(short_sha["body"]).replace(
            current_sha, current_sha[:10]
        )
        add(
            "clean-issue-short-sha",
            "clean issue comment",
            "10-character marker",
            "malformed",
            short_sha,
        )
        missing_marker = clone(clean_issue)
        missing_marker["body"] = "Codex Review: Didn't find any major issues."
        add(
            "clean-issue-missing-marker",
            "clean issue comment",
            "missing marker",
            "malformed",
            missing_marker,
        )
        duplicate_marker = clone(clean_issue)
        duplicate_marker["body"] = (
            f"{duplicate_marker['body']}\n\n**Reviewed commit:** `{current_sha}`"
        )
        add(
            "clean-issue-duplicate-marker",
            "clean issue comment",
            "duplicate marker",
            "malformed",
            duplicate_marker,
        )
        mixed_case_sha = clone(clean_issue)
        mixed_case_sha["body"] = str(mixed_case_sha["body"]).replace(
            current_sha, current_sha.upper()
        )
        add(
            "clean-issue-mixed-case-sha",
            "clean issue comment",
            "uppercase SHA text",
            "malformed",
            mixed_case_sha,
        )
        mismatched_sha = clone(clean_issue)
        mismatched_sha["body"] = str(mismatched_sha["body"]).replace(
            current_sha, other_sha
        )
        add(
            "clean-issue-mismatched-sha",
            "clean issue comment",
            "different full SHA",
            "malformed",
            mismatched_sha,
        )
        unlisted_tagline = clone(clean_issue)
        unlisted_tagline["body"] = str(unlisted_tagline["body"]).replace(
            "issues.", "issues. Nice."
        )
        add(
            "clean-issue-unlisted-tagline",
            "clean issue comment",
            "unlisted tagline",
            "malformed",
            unlisted_tagline,
        )
        extra_footer = clone(clean_issue)
        extra_footer["body"] = f"{extra_footer['body']}\n\nUnexpected footer"
        add(
            "clean-issue-extra-footer",
            "clean issue comment",
            "unlisted footer",
            "malformed",
            extra_footer,
        )
        containing_finding = clone(clean_issue)
        containing_finding["body"] = (
            f"{containing_finding['body']}\n"
            "- [P1] Example finding — "
            "https://github.com/OWNER/REPO/blob/"
            f"{current_sha}/path/to/file.py#L10"
        )
        add(
            "clean-issue-containing-finding",
            "clean issue comment",
            "appended finding line",
            "malformed",
            containing_finding,
        )
        empty_review = clone(clean_review)
        empty_review["body"] = ""
        add(
            "clean-review-empty",
            "clean pull-request review",
            "empty body",
            "malformed",
            empty_review,
        )
        punctuated_review = clone(clean_review)
        punctuated_review["body"] = "No findings!"
        add(
            "clean-review-punctuation",
            "clean pull-request review",
            "`No findings!`",
            "malformed",
            punctuated_review,
        )
        looks_good_review = clone(clean_review)
        looks_good_review["body"] = "Looks good."
        add(
            "clean-review-looks-good",
            "clean pull-request review",
            "`Looks good.`",
            "malformed",
            looks_good_review,
        )
        pending_review = clone(clean_review)
        pending_review["state"] = "PENDING"
        add(
            "review-pending-terminal-body",
            "pull-request review state",
            "`PENDING` with clean-shaped body",
            "nonterminal",
            pending_review,
        )
        dismissed_review = clone(clean_review)
        dismissed_review["state"] = "DISMISSED"
        add(
            "review-dismissed-terminal-body",
            "pull-request review state",
            "`DISMISSED` with clean-shaped body",
            "malformed",
            dismissed_review,
        )
        missing_state_review = clone(clean_review)
        missing_state_review.pop("state")
        add(
            "review-missing-state-terminal-body",
            "pull-request review state",
            "missing state with clean-shaped body",
            "malformed",
            missing_state_review,
        )
        unknown_state_review = clone(clean_review)
        unknown_state_review["state"] = "QUEUED"
        add(
            "review-unknown-state-terminal-body",
            "pull-request review state",
            "unknown state with clean-shaped body",
            "malformed",
            unknown_state_review,
        )
        missing_state_inline_parent = clone(inline_parent)
        missing_state_inline_parent.pop("state")
        add(
            "inline-parent-missing-state",
            "pull-request review state",
            "missing state with associated inline child",
            "malformed",
            missing_state_inline_parent,
        )
        cross_repository = clone(finding)
        cross_repository["body"] = str(cross_repository["body"]).replace(
            "/OWNER/REPO/", "/OTHER/REPO/"
        )
        add(
            "finding-cross-repository",
            "top-level finding",
            "different repository",
            "malformed",
            cross_repository,
        )
        short_finding_sha = clone(finding)
        short_finding_sha["body"] = str(short_finding_sha["body"]).replace(
            current_sha, current_sha[:10]
        )
        add(
            "finding-short-sha",
            "top-level finding",
            "10-character URL SHA",
            "malformed",
            short_finding_sha,
        )
        mixed_sha = clone(finding)
        mixed_sha["body"] = (
            f"{mixed_sha['body']}\n"
            "- [P2] Another finding — "
            "https://github.com/OWNER/REPO/blob/"
            f"{other_sha}/path/to/other.py#L20"
        )
        add(
            "finding-mixed-sha",
            "top-level finding",
            "two finding lines with different SHAs",
            "malformed",
            mixed_sha,
        )
        bad_percent = clone(finding)
        bad_percent["body"] = str(bad_percent["body"]).replace(
            "path/to/file.py", "path%2fto/file.py"
        )
        add(
            "finding-bad-percent-escape",
            "top-level finding",
            "`%2f` in path",
            "malformed",
            bad_percent,
        )
        bad_line_anchor = clone(finding)
        bad_line_anchor["body"] = str(bad_line_anchor["body"]).replace("#L10", "#L0")
        add(
            "finding-bad-line-anchor",
            "top-level finding",
            "zero line anchor",
            "malformed",
            bad_line_anchor,
        )
        no_children = clone(inline_parent)
        no_children["children"] = []
        add(
            "inline-parent-empty-children",
            "inline-parent review",
            "no child",
            "malformed",
            no_children,
        )
        wrong_parent = clone(inline_parent)
        wrong_parent["children"][0]["pull_request_review_id"] = review_id + 1
        add(
            "inline-parent-wrong-parent",
            "inline-parent review",
            "different `pull_request_review_id`",
            "malformed",
            wrong_parent,
        )
        wrong_child_commit = clone(inline_parent)
        wrong_child_commit["children"][0]["commit_id"] = other_sha
        add(
            "inline-parent-wrong-child-commit",
            "inline-parent review",
            "mismatched child `commit_id`",
            "malformed",
            wrong_child_commit,
        )
        wrong_child_sha = clone(inline_parent)
        wrong_child_sha["children"][0]["original_commit_id"] = other_sha
        add(
            "inline-parent-wrong-original-commit",
            "inline-parent review",
            "mismatched child `original_commit_id`",
            "malformed",
            wrong_child_sha,
        )

        positive_branches = {
            branch
            for _, branch, _, expected, _ in fixtures
            if expected in ("clean", "findings")
        }
        self.assertEqual(
            positive_branches,
            {
                "clean issue comment",
                "clean pull-request review",
                "top-level finding",
                "inline-parent review",
            },
        )
        for name, branch, mutation, expected, record in fixtures:
            with self.subTest(terminal_grammar_fixture=name):
                self.assertIn(
                    f"| `{name}` | {branch} | {mutation} | `{expected}` |",
                    authority,
                )
                self.assertEqual(classify(record), expected)

        boolean_clean_review_id = clone(clean_review)
        boolean_clean_review_id["id"] = True
        self.assertEqual(classify(boolean_clean_review_id), "malformed")

        boolean_child_parent = clone(inline_parent)
        boolean_child_parent["id"] = 1
        boolean_child_parent["children"][0]["pull_request_review_id"] = True
        self.assertEqual(classify(boolean_child_parent), "malformed")

        for child_field in ("normalized_body", "thread_id", "thread_resolved"):
            incomplete_child = clone(inline_parent)
            incomplete_child["children"][0].pop(child_field)
            with self.subTest(inline_child_missing_closed_field=child_field):
                self.assertEqual(classify(incomplete_child), "malformed")

        mismatched_child_normalization = clone(inline_parent)
        mismatched_child_normalization["children"][0]["normalized_body"] = (
            "Different normalized body"
        )
        self.assertEqual(classify(mismatched_child_normalization), "malformed")

        empty_child_body = clone(inline_parent)
        empty_child_body["children"][0]["body"] = ""
        empty_child_body["children"][0]["normalized_body"] = ""
        self.assertEqual(classify(empty_child_body), "malformed")

        resolved_child = clone(inline_parent)
        resolved_child["children"][0]["thread_resolved"] = True
        self.assertEqual(classify(resolved_child), "findings")

        def invalid_state_terminal_signal(record: dict[str, object]) -> bool:
            if record.get("channel") != "review" or not exact_provider(record):
                return False
            state = record.get("state")
            if state == "PENDING" or state in (
                "APPROVED",
                "COMMENTED",
                "CHANGES_REQUESTED",
            ):
                return False
            body = normalize_body(record.get("body"))
            children = record.get("children")
            return (
                state == "DISMISSED"
                or bool(body)
                or (isinstance(children, list) and bool(children))
            )

        def select_terminal(records: list[dict[str, object]]) -> str:
            if any(invalid_state_terminal_signal(record) for record in records):
                return "inconclusive"
            terminal = [
                (record["submitted_at"], classify(record))
                for record in records
                if classify(record) != "nonterminal"
            ]
            if not terminal or any(outcome == "malformed" for _, outcome in terminal):
                return "inconclusive"
            return max(terminal)[1]

        newer_clean_review = clone(clean_review)
        newer_clean_review["submitted_at"] = 20
        for invalid_state in ("DISMISSED", None, "UNKNOWN"):
            invalid_state_review = clone(clean_review)
            invalid_state_review["submitted_at"] = 10
            if invalid_state is None:
                invalid_state_review.pop("state")
            else:
                invalid_state_review["state"] = invalid_state
            with self.subTest(invalid_state_global_blocker=invalid_state):
                self.assertEqual(
                    select_terminal([invalid_state_review, newer_clean_review]),
                    "inconclusive",
                )

        pending_review_with_newer_clean = clone(clean_review)
        pending_review_with_newer_clean["state"] = "PENDING"
        pending_review_with_newer_clean["submitted_at"] = 10
        self.assertEqual(
            select_terminal([pending_review_with_newer_clean, newer_clean_review]),
            "clean",
        )

        clean_lead = "Codex Review: Didn't find any major issues."
        marker = f"**Reviewed commit:** `{current_sha}`"
        for accepted_tagline in (
            " :rocket:",
            " 🚀",
            " Nice work!",
            " You're on a roll?",
        ):
            tagged = clone(clean_issue)
            tagged["body"] = f"{clean_lead}{accepted_tagline}\n\n{marker}"
            with self.subTest(accepted_clean_tagline=accepted_tagline):
                self.assertEqual(classify(tagged), "clean")
        disclosed = clone(clean_issue)
        disclosed["body"] = f"{clean_issue['body']}\n\n{disclosure}"
        self.assertEqual(classify(disclosed), "clean")

        selection_pagination = {
            "issue_comments": True,
            "reviews": True,
            "inline_comments": True,
            "review_threads": True,
        }

        def report_typed_equal(left: object, right: object) -> bool:
            if type(left) is not type(right):
                return False
            if isinstance(left, dict):
                assert isinstance(right, dict)
                return set(left) == set(right) and all(
                    report_typed_equal(left[key], right[key]) for key in left
                )
            if isinstance(left, list):
                assert isinstance(right, list)
                return len(left) == len(right) and all(
                    report_typed_equal(left_item, right_item)
                    for left_item, right_item in zip(left, right, strict=True)
                )
            return left == right

        def report_exact_true_flags(
            value: object,
            expected: dict[str, bool],
        ) -> bool:
            return (
                isinstance(value, dict)
                and set(value) == set(expected)
                and all(value[key] is True for key in expected)
            )

        def complete_terminal_artifact(
            record: dict[str, object],
        ) -> dict[str, object]:
            snapshot = clone(record)
            body = normalize_body(snapshot.get("body"))
            assert body is not None
            snapshot["normalized_body"] = body
            if snapshot.get("channel") == "review":
                artifact_id = snapshot.get("id")
                children = snapshot.get("children")
                assert type(artifact_id) is int
                assert isinstance(children, list)
                snapshot["url"] = (
                    "https://github.com/OWNER/REPO/pull/1"
                    f"#pullrequestreview-{artifact_id}"
                )
                snapshot["submitted_at"] = 100
                snapshot["server_time"] = 100
                snapshot["server_time_field"] = "submitted_at"
                snapshot["associated_inline_comments"] = {
                    "pagination_complete": True,
                    "records": clone(children),
                }
                snapshot["review_thread_join"] = {
                    "pagination_complete": True,
                    "records": [
                        {
                            "child_id": child_record["id"],
                            "thread_id": child_record["thread_id"],
                            "is_resolved": child_record["thread_resolved"],
                            "pull_request_review_id": artifact_id,
                        }
                        for child_record in children
                    ],
                }
            else:
                artifact_id = 234567890
                snapshot["id"] = artifact_id
                snapshot["api_url"] = (
                    "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                    f"{artifact_id}"
                )
                snapshot["url"] = (
                    f"https://github.com/OWNER/REPO/pull/1#issuecomment-{artifact_id}"
                )
                snapshot["created_at"] = 100
                snapshot["updated_at"] = 100
                snapshot["server_time"] = 100
                snapshot["server_time_field"] = "created_at"
                snapshot["parsed_commit"] = current_sha
            return snapshot

        def selection_snapshot_for(
            artifact: dict[str, object],
            outcome: str,
        ) -> dict[str, object]:
            children = artifact.get("children")
            child_records = children if isinstance(children, list) else []
            return {
                "complete": True,
                "lifecycle": {
                    "state": "open",
                    "merged": False,
                    "merged_at": None,
                },
                "scope": {
                    "repository": "OWNER/REPO",
                    "pr": 1,
                    "pr_merge_base": "1" * 40,
                    "head": current_sha,
                },
                "pagination": clone(selection_pagination),
                "terminal_candidates": [
                    {
                        "kind": (
                            "pull-request-review"
                            if artifact.get("channel") == "review"
                            else "issue-comment"
                        ),
                        "id": artifact.get("id"),
                        "url": artifact.get("url"),
                        "server_time": artifact.get("server_time"),
                        "outcome": outcome,
                        "commit": (
                            artifact.get("commit_id")
                            if artifact.get("channel") == "review"
                            else artifact.get("parsed_commit")
                        ),
                    }
                ],
                "malformed_blockers": [],
                "thread_findings": [
                    {
                        "child_id": child_record["id"],
                        "thread_id": child_record["thread_id"],
                        "is_resolved": child_record["thread_resolved"],
                        "pull_request_review_id": child_record[
                            "pull_request_review_id"
                        ],
                    }
                    for child_record in child_records
                ],
            }

        def terminal_report(
            record: dict[str, object],
            claimed_outcome: str,
        ) -> dict[str, object]:
            artifact = complete_terminal_artifact(record)
            selection = selection_snapshot_for(artifact, claimed_outcome)
            return {
                "kind": (
                    "pull-request-review"
                    if artifact.get("channel") == "review"
                    else "issue-comment"
                ),
                "selection_snapshots": {
                    "initial": clone(selection),
                    "final": clone(selection),
                },
                "artifact": {
                    "initial_snapshot": clone(artifact),
                    "final_snapshot": clone(artifact),
                },
                "claimed_outcome": claimed_outcome,
            }

        def classify_terminal_report(report: object) -> str:
            if not isinstance(report, dict) or set(report) != {
                "kind",
                "selection_snapshots",
                "artifact",
                "claimed_outcome",
            }:
                return "inconclusive"
            selection_snapshots = report.get("selection_snapshots")
            artifact_snapshots = report.get("artifact")
            if (
                not isinstance(selection_snapshots, dict)
                or set(selection_snapshots) != {"initial", "final"}
                or not isinstance(artifact_snapshots, dict)
                or set(artifact_snapshots) != {"initial_snapshot", "final_snapshot"}
                or not report_typed_equal(
                    selection_snapshots.get("initial"),
                    selection_snapshots.get("final"),
                )
                or not report_typed_equal(
                    artifact_snapshots.get("initial_snapshot"),
                    artifact_snapshots.get("final_snapshot"),
                )
            ):
                return "inconclusive"
            selection = selection_snapshots.get("final")
            artifact = artifact_snapshots.get("final_snapshot")
            if not isinstance(selection, dict) or not isinstance(artifact, dict):
                return "inconclusive"
            if (
                set(selection)
                != {
                    "complete",
                    "lifecycle",
                    "scope",
                    "pagination",
                    "terminal_candidates",
                    "malformed_blockers",
                    "thread_findings",
                }
                or selection.get("complete") is not True
                or not report_typed_equal(
                    selection.get("lifecycle"),
                    {"state": "open", "merged": False, "merged_at": None},
                )
                or not report_typed_equal(
                    selection.get("scope"),
                    {
                        "repository": "OWNER/REPO",
                        "pr": 1,
                        "pr_merge_base": "1" * 40,
                        "head": current_sha,
                    },
                )
                or not report_exact_true_flags(
                    selection.get("pagination"), selection_pagination
                )
                or selection.get("malformed_blockers") != []
            ):
                return "inconclusive"

            body = normalize_body(artifact.get("body"))
            if (
                body is None
                or artifact.get("normalized_body") != body
                or type(artifact.get("id")) is not int
                or artifact["id"] <= 0
            ):
                return "inconclusive"
            channel = artifact.get("channel")
            if channel == "review":
                artifact_id = artifact["id"]
                children = artifact.get("children")
                associated = artifact.get("associated_inline_comments")
                thread_join = artifact.get("review_thread_join")
                if (
                    set(artifact)
                    != {
                        "channel",
                        "id",
                        "user_login",
                        "user_type",
                        "state",
                        "commit_id",
                        "body",
                        "children",
                        "normalized_body",
                        "url",
                        "submitted_at",
                        "server_time",
                        "server_time_field",
                        "associated_inline_comments",
                        "review_thread_join",
                    }
                    or artifact.get("url")
                    != (
                        "https://github.com/OWNER/REPO/pull/1"
                        f"#pullrequestreview-{artifact_id}"
                    )
                    or type(artifact.get("submitted_at")) is not int
                    or artifact.get("submitted_at") != 100
                    or type(artifact.get("server_time")) is not int
                    or artifact.get("server_time") != 100
                    or artifact.get("server_time_field") != "submitted_at"
                    or not isinstance(children, list)
                    or not isinstance(associated, dict)
                    or set(associated) != {"pagination_complete", "records"}
                    or associated.get("pagination_complete") is not True
                    or not report_typed_equal(associated.get("records"), children)
                    or not isinstance(thread_join, dict)
                    or set(thread_join) != {"pagination_complete", "records"}
                    or thread_join.get("pagination_complete") is not True
                    or not isinstance(thread_join.get("records"), list)
                ):
                    return "inconclusive"
                expected_thread_records: list[dict[str, object]] = []
                child_ids: set[int] = set()
                for child_record in children:
                    if (
                        not exact_inline_child(
                            child_record,
                            parent_id=artifact_id,
                            commit_id=str(artifact.get("commit_id")),
                        )
                        or child_record["id"] in child_ids
                    ):
                        return "inconclusive"
                    child_ids.add(child_record["id"])
                    expected_thread_records.append(
                        {
                            "child_id": child_record["id"],
                            "thread_id": child_record["thread_id"],
                            "is_resolved": child_record["thread_resolved"],
                            "pull_request_review_id": artifact_id,
                        }
                    )
                if not report_typed_equal(
                    thread_join.get("records"), expected_thread_records
                ):
                    return "inconclusive"
            elif channel == "issue-comment":
                artifact_id = artifact["id"]
                if (
                    set(artifact)
                    != {
                        "channel",
                        "user_login",
                        "user_type",
                        "app_slug",
                        "body",
                        "normalized_body",
                        "id",
                        "api_url",
                        "url",
                        "created_at",
                        "updated_at",
                        "server_time",
                        "server_time_field",
                        "parsed_commit",
                    }
                    or artifact.get("api_url")
                    != (
                        "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                        f"{artifact_id}"
                    )
                    or artifact.get("url")
                    != (
                        "https://github.com/OWNER/REPO/pull/1"
                        f"#issuecomment-{artifact_id}"
                    )
                    or artifact.get("app_slug") != "chatgpt-codex-connector"
                    or type(artifact.get("created_at")) is not int
                    or artifact.get("created_at") != 100
                    or type(artifact.get("updated_at")) is not int
                    or artifact.get("updated_at") != 100
                    or type(artifact.get("server_time")) is not int
                    or artifact.get("server_time") != 100
                    or artifact.get("server_time_field") != "created_at"
                    or artifact.get("parsed_commit") != current_sha
                ):
                    return "inconclusive"
            else:
                return "inconclusive"

            classified = classify(artifact)
            expected_kind = (
                "pull-request-review" if channel == "review" else "issue-comment"
            )
            expected_selection = selection_snapshot_for(artifact, classified)
            if (
                classified not in ("clean", "findings")
                or report.get("kind") != expected_kind
                or report.get("claimed_outcome") != classified
                or not report_typed_equal(selection, expected_selection)
            ):
                return "inconclusive"
            return classified

        clean_review_report = terminal_report(clean_review, "clean")
        self.assertEqual(
            classify_terminal_report(clean_review_report),
            "clean",
        )
        self.assertEqual(
            classify_terminal_report(terminal_report(clean_issue, "clean")),
            "clean",
        )
        inline_finding_report = terminal_report(
            approved_with_inline_finding,
            "findings",
        )
        self.assertEqual(
            classify_terminal_report(inline_finding_report),
            "findings",
        )

        boolean_child_parent_report_record = clone(inline_parent)
        boolean_child_parent_report_record["id"] = 1
        boolean_child_parent_report_record["children"][0]["pull_request_review_id"] = (
            True
        )
        self.assertEqual(
            classify_terminal_report(
                terminal_report(boolean_child_parent_report_record, "findings")
            ),
            "inconclusive",
        )

        for child_field in ("normalized_body", "thread_id", "thread_resolved"):
            incomplete_child_report = clone(inline_finding_report)
            for snapshot_name in ("initial_snapshot", "final_snapshot"):
                artifact_snapshot = incomplete_child_report["artifact"][snapshot_name]
                artifact_snapshot["children"][0].pop(child_field)
                artifact_snapshot["associated_inline_comments"]["records"][0].pop(
                    child_field
                )
            with self.subTest(terminal_report_child_missing_field=child_field):
                self.assertEqual(
                    classify_terminal_report(incomplete_child_report),
                    "inconclusive",
                )

        mismatched_child_thread_report = clone(inline_finding_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            report_child = mismatched_child_thread_report["artifact"][snapshot_name][
                "children"
            ][0]
            report_child["thread_id"] = "PRRT_different"
            associated_child = mismatched_child_thread_report["artifact"][
                snapshot_name
            ]["associated_inline_comments"]["records"][0]
            associated_child["thread_id"] = "PRRT_different"
        self.assertEqual(
            classify_terminal_report(mismatched_child_thread_report),
            "inconclusive",
        )

        numeric_child_resolution_report = clone(inline_finding_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact_snapshot = numeric_child_resolution_report["artifact"][
                snapshot_name
            ]
            artifact_snapshot["children"][0]["thread_resolved"] = 0
            artifact_snapshot["associated_inline_comments"]["records"][0][
                "thread_resolved"
            ] = 0
            artifact_snapshot["review_thread_join"]["records"][0]["is_resolved"] = 0
        for snapshot_name in ("initial", "final"):
            numeric_child_resolution_report["selection_snapshots"][snapshot_name][
                "thread_findings"
            ][0]["is_resolved"] = 0
        self.assertEqual(
            classify_terminal_report(numeric_child_resolution_report),
            "inconclusive",
        )

        empty_child_body_report = clone(inline_finding_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact_snapshot = empty_child_body_report["artifact"][snapshot_name]
            for child_record in (
                artifact_snapshot["children"][0],
                artifact_snapshot["associated_inline_comments"]["records"][0],
            ):
                child_record["body"] = ""
                child_record["normalized_body"] = ""
        self.assertEqual(
            classify_terminal_report(empty_child_body_report),
            "inconclusive",
        )

        child_schema_extension_report = clone(inline_finding_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact_snapshot = child_schema_extension_report["artifact"][snapshot_name]
            artifact_snapshot["children"][0]["authority_override"] = True
            artifact_snapshot["associated_inline_comments"]["records"][0][
                "authority_override"
            ] = True
        self.assertEqual(
            classify_terminal_report(child_schema_extension_report),
            "inconclusive",
        )

        for page_field in ("associated_inline_comments", "review_thread_join"):
            extended_page_report = clone(inline_finding_report)
            for snapshot_name in ("initial_snapshot", "final_snapshot"):
                extended_page_report["artifact"][snapshot_name][page_field][
                    "authority_override"
                ] = True
            with self.subTest(terminal_report_page_unknown_key=page_field):
                self.assertEqual(
                    classify_terminal_report(extended_page_report),
                    "inconclusive",
                )

        extended_thread_record_report = clone(inline_finding_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            extended_thread_record_report["artifact"][snapshot_name][
                "review_thread_join"
            ]["records"][0]["authority_override"] = True
        self.assertEqual(
            classify_terminal_report(extended_thread_record_report),
            "inconclusive",
        )

        sparse_terminal_report = {
            "kind": "pull-request-review",
            "id": review_id,
            "commit_id": current_sha,
            "claimed_outcome": "clean",
        }
        self.assertEqual(
            classify_terminal_report(sparse_terminal_report),
            "inconclusive",
        )

        report_schema_extension = clone(clean_review_report)
        report_schema_extension["authority_override"] = True
        self.assertEqual(
            classify_terminal_report(report_schema_extension),
            "inconclusive",
        )

        selection_wrapper_extension = clone(clean_review_report)
        selection_wrapper_extension["selection_snapshots"]["authority_override"] = True
        self.assertEqual(
            classify_terminal_report(selection_wrapper_extension),
            "inconclusive",
        )

        artifact_wrapper_extension = clone(clean_review_report)
        artifact_wrapper_extension["artifact"]["authority_override"] = True
        self.assertEqual(
            classify_terminal_report(artifact_wrapper_extension),
            "inconclusive",
        )

        selection_schema_extension = clone(clean_review_report)
        for snapshot_name in ("initial", "final"):
            selection_schema_extension["selection_snapshots"][snapshot_name][
                "authority_override"
            ] = True
        self.assertEqual(
            classify_terminal_report(selection_schema_extension),
            "inconclusive",
        )

        artifact_schema_extension = clone(clean_review_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact_schema_extension["artifact"][snapshot_name][
                "authority_override"
            ] = True
        self.assertEqual(
            classify_terminal_report(artifact_schema_extension),
            "inconclusive",
        )

        missing_children_page = clone(clean_review_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            missing_children_page["artifact"][snapshot_name].pop(
                "associated_inline_comments"
            )
        self.assertEqual(
            classify_terminal_report(missing_children_page),
            "inconclusive",
        )

        lookalike_report = clone(clean_review_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            lookalike_report["artifact"][snapshot_name]["user_login"] = (
                "ChatGPT-Codex-Connector[bot]"
            )
        self.assertEqual(
            classify_terminal_report(lookalike_report),
            "inconclusive",
        )

        empty_candidate_selection = clone(clean_review_report)
        for snapshot_name in ("initial", "final"):
            empty_candidate_selection["selection_snapshots"][snapshot_name][
                "terminal_candidates"
            ] = []
        self.assertEqual(
            classify_terminal_report(empty_candidate_selection),
            "inconclusive",
        )

        issue_missing_app = terminal_report(clean_issue, "clean")
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            issue_missing_app["artifact"][snapshot_name].pop("app_slug")
        self.assertEqual(
            classify_terminal_report(issue_missing_app),
            "inconclusive",
        )

        terminal_report_final_drift = clone(clean_review_report)
        terminal_report_final_drift["artifact"]["final_snapshot"]["body"] = (
            "Changed body."
        )
        self.assertEqual(
            classify_terminal_report(terminal_report_final_drift),
            "inconclusive",
        )

        boolean_artifact_id = clone(clean_review_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            boolean_artifact_id["artifact"][snapshot_name]["id"] = True
            boolean_artifact_id["artifact"][snapshot_name]["url"] = (
                "https://github.com/OWNER/REPO/pull/1#pullrequestreview-True"
            )
        for snapshot_name in ("initial", "final"):
            candidate = boolean_artifact_id["selection_snapshots"][snapshot_name][
                "terminal_candidates"
            ][0]
            candidate["id"] = True
            candidate["url"] = (
                "https://github.com/OWNER/REPO/pull/1#pullrequestreview-True"
            )
        self.assertEqual(
            classify_terminal_report(boolean_artifact_id),
            "inconclusive",
        )

        initial_only_boolean_alias = clone(clean_review_report)
        initial_only_boolean_alias["selection_snapshots"]["initial"]["pagination"][
            "reviews"
        ] = 1
        self.assertEqual(
            classify_terminal_report(initial_only_boolean_alias),
            "inconclusive",
        )

        numeric_false_lifecycle = clone(clean_review_report)
        for snapshot_name in ("initial", "final"):
            numeric_false_lifecycle["selection_snapshots"][snapshot_name]["lifecycle"][
                "merged"
            ] = 0
        self.assertEqual(
            classify_terminal_report(numeric_false_lifecycle),
            "inconclusive",
        )

        floating_submitted_at = clone(clean_review_report)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            floating_submitted_at["artifact"][snapshot_name]["submitted_at"] = 100.0
        self.assertEqual(
            classify_terminal_report(floating_submitted_at),
            "inconclusive",
        )

        wrong_claim = clone(inline_finding_report)
        wrong_claim["claimed_outcome"] = "clean"
        self.assertEqual(
            classify_terminal_report(wrong_claim),
            "inconclusive",
        )

        normalized_authority = " ".join(authority.split()).lower()
        for report_anchor in (
            "selection_snapshots.initial",
            "artifact.initial_snapshot",
            "associated inline-comment page/join",
            "every child record includes its stable id/url",
            "closed object schemas and json type identity",
            "numeric `0` / `1` are never boolean pagination or resolution values",
            "an `approved` / `no findings.` review with zero children",
            "performed_via_github_app.slug",
            "a sparse summary cannot prove the closed grammar",
        ):
            self.assertIn(report_anchor, normalized_authority)

    def test_thumbs_up_clean_reference_matrix(self) -> None:
        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        exact_login = "chatgpt-codex-connector[bot]"
        current_repository = "OWNER/REPO"
        current_pr = 1
        current_head = "0123456789abcdef0123456789abcdef01234567"
        current_merge_base = "1111111111111111111111111111111111111111"
        current_scope_key = (
            current_repository,
            current_pr,
            current_merge_base,
            current_head,
        )
        history_window_seconds = 30 * 24 * 60 * 60
        history_as_of_server_time = 3_000_000
        history_start_exclusive = history_as_of_server_time - history_window_seconds
        declaration_pr = 99
        declaration_artifact_id = 9_001
        declaration_text = (
            "If Codex has suggestions, it will comment; otherwise it will react "
            "with 👍."
        )
        declaration_record = {
            "authority_kind": "exact-provider-github-artifact",
            "repository": current_repository,
            "pull_request": declaration_pr,
            "artifact_id": declaration_artifact_id,
            "api_url": (
                "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                f"{declaration_artifact_id}"
            ),
            "html_url": (
                f"https://github.com/{current_repository}/pull/{declaration_pr}"
                f"#issuecomment-{declaration_artifact_id}"
            ),
            "channel": "issue-comment",
            "user_login": exact_login,
            "user_type": "Bot",
            "app_slug": "chatgpt-codex-connector",
            "created_at": 100,
            "updated_at": 100,
            "server_time": 100,
            "server_time_field": "created_at",
            "body": declaration_text,
            "asserted_text": declaration_text,
            "github_reaction_content": "+1",
            "github_reaction_glyph": "👍",
            "normalization": "crlf-and-cr-to-lf+utf8",
            "normalized_sha256": hashlib.sha256(
                declaration_text.encode("utf-8")
            ).hexdigest(),
        }
        declaration = {
            "initial_snapshot": declaration_record,
            "final_snapshot": json.loads(json.dumps(declaration_record)),
        }
        required_pagination = {
            "request_comments": True,
            "request_reactions": True,
            "issue_comments": True,
            "reviews": True,
            "inline_comments": True,
            "review_threads": True,
        }
        required_universe_pagination = {
            "pull_requests": True,
            "issue_comments": True,
            "reviews": True,
            "inline_comments": True,
            "review_threads": True,
            "request_reactions": True,
        }
        empty_evidence_state = {
            "terminal_payloads": [],
            "malformed_terminal_artifacts": [],
            "active_top_level_findings": [],
            "unresolved_thread_findings": [],
        }

        def clone(value: object) -> object:
            return json.loads(json.dumps(value))

        def typed_json_equal(left: object, right: object) -> bool:
            if type(left) is not type(right):
                return False
            if isinstance(left, dict):
                assert isinstance(right, dict)
                return set(left) == set(right) and all(
                    typed_json_equal(left[key], right[key]) for key in left
                )
            if isinstance(left, list):
                assert isinstance(right, list)
                return len(left) == len(right) and all(
                    typed_json_equal(left_item, right_item)
                    for left_item, right_item in zip(left, right, strict=True)
                )
            return left == right

        def exact_true_flags(value: object, expected: dict[str, bool]) -> bool:
            return (
                isinstance(value, dict)
                and set(value) == set(expected)
                and all(value[key] is True for key in expected)
            )

        def declaration_is_authoritative(value: object) -> bool:
            if not isinstance(value, dict) or set(value) != {
                "initial_snapshot",
                "final_snapshot",
            }:
                return False
            initial = value.get("initial_snapshot")
            final = value.get("final_snapshot")
            if (
                not isinstance(initial, dict)
                or not isinstance(final, dict)
                or not typed_json_equal(initial, final)
            ):
                return False
            expected_snapshot_keys = {
                "authority_kind",
                "repository",
                "pull_request",
                "artifact_id",
                "api_url",
                "html_url",
                "channel",
                "user_login",
                "user_type",
                "app_slug",
                "created_at",
                "updated_at",
                "server_time",
                "server_time_field",
                "body",
                "asserted_text",
                "github_reaction_content",
                "github_reaction_glyph",
                "normalization",
                "normalized_sha256",
            }
            artifact_id = final.get("artifact_id")
            pull_request = final.get("pull_request")
            created_at = final.get("created_at")
            updated_at = final.get("updated_at")
            body = final.get("body")
            asserted_text = final.get("asserted_text")
            if (
                set(final) != expected_snapshot_keys
                or final.get("authority_kind") != "exact-provider-github-artifact"
                or final.get("repository") != current_repository
                or type(pull_request) is not int
                or pull_request <= 0
                or type(artifact_id) is not int
                or artifact_id <= 0
                or final.get("api_url")
                != (
                    "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                    f"{artifact_id}"
                )
                or final.get("html_url")
                != (
                    f"https://github.com/{current_repository}/pull/{pull_request}"
                    f"#issuecomment-{artifact_id}"
                )
                or final.get("channel") != "issue-comment"
                or final.get("user_login") != exact_login
                or final.get("user_type") != "Bot"
                or final.get("app_slug") != "chatgpt-codex-connector"
                or type(created_at) is not int
                or type(updated_at) is not int
                or created_at <= 0
                or updated_at != created_at
                or type(final.get("server_time")) is not int
                or final.get("server_time") != created_at
                or final.get("server_time_field") != "created_at"
                or not isinstance(body, str)
                or asserted_text != declaration_text
                or final.get("github_reaction_content") != "+1"
                or final.get("github_reaction_glyph") != "👍"
                or final.get("normalization") != "crlf-and-cr-to-lf+utf8"
            ):
                return False
            try:
                normalized_body = body.replace("\r\n", "\n").replace("\r", "\n")
                normalized_body.encode("utf-8", errors="strict")
                normalized_bytes = (
                    asserted_text.replace("\r\n", "\n")
                    .replace("\r", "\n")
                    .encode("utf-8", errors="strict")
                )
            except (AttributeError, UnicodeEncodeError):
                return False
            return (
                normalized_body.split("\n").count(declaration_text) == 1
                and final.get("normalized_sha256")
                == hashlib.sha256(normalized_bytes).hexdigest()
            )

        def request(
            request_id: int,
            created_at: int,
            *,
            pr: int,
            updated_at: int | None = None,
        ) -> dict[str, object]:
            request_server_time = created_at if updated_at is None else updated_at
            return {
                "id": request_id,
                "url": (
                    f"https://github.com/{current_repository}/pull/{pr}"
                    f"#issuecomment-{request_id}"
                ),
                "created_at": created_at,
                "updated_at": created_at if updated_at is None else updated_at,
                "request_server_time": request_server_time,
                "request_server_time_field": (
                    "created_at"
                    if updated_at is None or updated_at == created_at
                    else "updated_at"
                ),
                "normalized_body": "@codex review",
            }

        def reaction(
            reaction_id: int | None,
            request_id: int,
            created_at: int,
            *,
            content: str = "+1",
            user_login: str | None = exact_login,
            user_type: str | None = "Bot",
        ) -> dict[str, object]:
            return {
                "id": reaction_id,
                "api_url": (
                    f"https://api.github.com/repos/OWNER/REPO/reactions/{reaction_id}"
                ),
                "parent_request_id": request_id,
                "parent_reactions_api_url": (
                    "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                    f"{request_id}/reactions?per_page=100"
                ),
                "created_at": created_at,
                "content": content,
                "user_login": user_login,
                "user_type": user_type,
            }

        snapshot_fields = (
            "complete",
            "pagination",
            "evidence_state",
            "lifecycle",
            "scope",
            "requests",
            "reactions",
            "selected_request_id",
            "selected_reaction_id",
            "candidate_basis",
        )
        record_fields = set(snapshot_fields) | {
            "initial_snapshot",
            "final_snapshot",
        }
        request_fields = {
            "id",
            "url",
            "created_at",
            "updated_at",
            "request_server_time",
            "request_server_time_field",
            "normalized_body",
        }
        reaction_fields = {
            "id",
            "api_url",
            "parent_request_id",
            "parent_reactions_api_url",
            "created_at",
            "content",
            "user_login",
            "user_type",
        }

        def record_snapshot(record: dict[str, object]) -> dict[str, object]:
            return {field: clone(record.get(field)) for field in snapshot_fields}

        def restamp(record: dict[str, object]) -> dict[str, object]:
            snapshot = record_snapshot(record)
            record["initial_snapshot"] = clone(snapshot)
            record["final_snapshot"] = clone(snapshot)
            return record

        def outcome(
            pr: int,
            head: str,
            requests: list[dict[str, object]],
            reactions: list[dict[str, object]],
            *,
            selected_request_id: int,
            selected_reaction_id: int,
            merge_base: str | None = None,
            candidate_server_time: int | None = None,
            stable_artifact_id: int | None = None,
        ) -> dict[str, object]:
            selected_reaction = next(
                (item for item in reactions if item.get("id") == selected_reaction_id),
                None,
            )
            resolved_merge_base = merge_base or f"{pr + 1000:040x}"
            record = {
                "complete": True,
                "pagination": clone(required_pagination),
                "evidence_state": clone(empty_evidence_state),
                "lifecycle": {
                    "state": "open",
                    "merged": False,
                    "merged_at": None,
                },
                "scope": {
                    "repository": current_repository,
                    "pr": pr,
                    "pr_merge_base": resolved_merge_base,
                    "head": head,
                },
                "requests": requests,
                "reactions": reactions,
                "selected_request_id": selected_request_id,
                "selected_reaction_id": selected_reaction_id,
                "candidate_basis": {
                    "kind": "reaction",
                    "server_time": (
                        selected_reaction.get("created_at")
                        if candidate_server_time is None
                        and isinstance(selected_reaction, dict)
                        else candidate_server_time
                    ),
                    "stable_artifact_id": (
                        selected_reaction_id
                        if stable_artifact_id is None
                        else stable_artifact_id
                    ),
                },
            }
            return restamp(record)

        def scope_key(record: dict[str, object]) -> tuple[object, ...] | None:
            scope = record.get("scope")
            if not isinstance(scope, dict) or set(scope) != {
                "repository",
                "pr",
                "pr_merge_base",
                "head",
            }:
                return None
            repository = scope.get("repository")
            pr = scope.get("pr")
            merge_base = scope.get("pr_merge_base")
            head = scope.get("head")
            if (
                repository != current_repository
                or type(pr) is not int
                or pr <= 0
                or not isinstance(merge_base, str)
                or re.fullmatch(r"[0-9a-f]{40}", merge_base) is None
                or not isinstance(head, str)
                or re.fullmatch(r"[0-9a-f]{40}", head) is None
            ):
                return None
            return (repository, pr, merge_base, head)

        def lifecycle_is_typed(
            record: dict[str, object],
            *,
            require_open: bool,
        ) -> bool:
            lifecycle = record.get("lifecycle")
            if not isinstance(lifecycle, dict) or set(lifecycle) != {
                "state",
                "merged",
                "merged_at",
            }:
                return False
            state = lifecycle.get("state")
            merged = lifecycle.get("merged")
            merged_at = lifecycle.get("merged_at")
            if state not in {"open", "closed"} or type(merged) is not bool:
                return False
            if require_open:
                return state == "open" and merged is False and merged_at is None
            if state == "open":
                return merged is False and merged_at is None
            if merged is False:
                return merged_at is None
            return (
                type(merged_at) is int
                and merged_at > 0
                and merged_at <= history_as_of_server_time
            )

        def complete_review_artifact(
            record: dict[str, object],
            artifact_id: int,
            server_time: int,
            *,
            artifact_kind: str = "terminal-payload",
            outcome: str = "clean",
            user_login: str = exact_login,
            user_type: str = "Bot",
        ) -> dict[str, object]:
            scope = clone(record.get("scope"))
            assert isinstance(scope, dict)
            pr = scope["pr"]
            head = scope["head"]
            if artifact_kind == "unresolved-thread-finding":
                if outcome != "findings":
                    raise AssertionError("unresolved thread fixture must be findings")
                state = "COMMENTED"
                body = ""
                grammar_status = "accepted"
                terminal_looking = True
            elif outcome == "clean":
                state = "APPROVED"
                body = "No findings."
                grammar_status = "accepted"
                terminal_looking = True
            elif outcome == "findings":
                state = "COMMENTED"
                body = (
                    "### 💡 Codex Review\n"
                    "- [P1] Fixture finding — "
                    f"https://github.com/{current_repository}/blob/{head}/"
                    "src/example.py#L1"
                )
                grammar_status = "accepted"
                terminal_looking = True
            elif outcome == "malformed":
                state = "APPROVED"
                body = "Looks good."
                grammar_status = "malformed"
                terminal_looking = True
            else:
                raise AssertionError(f"unsupported fixture outcome: {outcome}")
            if artifact_kind == "unresolved-thread-finding":
                child_id = (artifact_id * 10) + 1
                thread_id = f"PRRT_{artifact_id}"
                associated_inline_comments = {
                    "pagination_complete": True,
                    "records": [
                        {
                            "id": child_id,
                            "url": (
                                f"https://github.com/{current_repository}/pull/{pr}"
                                f"#discussion_r{child_id}"
                            ),
                            "user_login": exact_login,
                            "user_type": "Bot",
                            "pull_request_review_id": artifact_id,
                            "commit_id": head,
                            "original_commit_id": head,
                            "body": "[P1] Fixture inline finding",
                            "normalized_body": "[P1] Fixture inline finding",
                            "thread_id": thread_id,
                        }
                    ],
                }
                review_thread_join = {
                    "pagination_complete": True,
                    "records": [
                        {
                            "thread_id": thread_id,
                            "is_resolved": False,
                            "comment_ids": [child_id],
                        }
                    ],
                }
            else:
                associated_inline_comments = {
                    "pagination_complete": True,
                    "records": [],
                }
                review_thread_join = {
                    "pagination_complete": True,
                    "records": [],
                }
            snapshot: dict[str, object] = {
                "complete": True,
                "artifact_kind": artifact_kind,
                "outcome": outcome,
                "channel": "pull-request-review",
                "id": artifact_id,
                "stable_artifact_id": artifact_id,
                "url": (
                    f"https://github.com/{current_repository}/pull/{pr}"
                    f"#pullrequestreview-{artifact_id}"
                ),
                "user_login": user_login,
                "user_type": user_type,
                "state": state,
                "body": body,
                "normalized_body": body,
                "grammar_status": grammar_status,
                "terminal_looking": terminal_looking,
                "submitted_at": server_time,
                "server_time": server_time,
                "server_time_field": "submitted_at",
                "commit_id": head,
                "scope": scope,
                "associated_inline_comments": associated_inline_comments,
                "review_thread_join": review_thread_join,
            }
            if artifact_kind == "unresolved-thread-finding":
                snapshot["thread_id"] = thread_id
                snapshot["thread_resolved"] = False
            return {
                "initial_snapshot": clone(snapshot),
                "final_snapshot": clone(snapshot),
            }

        def validate_candidate_artifact(
            value: object,
            *,
            expected_kind: str,
            expected_scope: tuple[object, ...],
        ) -> tuple[int, int, str, str, str] | None:
            if not isinstance(value, dict):
                return None
            initial = value.get("initial_snapshot")
            final = value.get("final_snapshot")
            if (
                set(value) != {"initial_snapshot", "final_snapshot"}
                or not isinstance(initial, dict)
                or not isinstance(final, dict)
                or not typed_json_equal(initial, final)
            ):
                return None
            repository, pr, merge_base, head = expected_scope
            artifact_id = final.get("id")
            server_time = final.get("server_time")
            body = final.get("body")
            outcome = final.get("outcome")
            channel = final.get("channel")
            expected_snapshot_keys = {
                "complete",
                "artifact_kind",
                "outcome",
                "channel",
                "id",
                "stable_artifact_id",
                "url",
                "user_login",
                "user_type",
                "state",
                "body",
                "normalized_body",
                "grammar_status",
                "terminal_looking",
                "submitted_at",
                "server_time",
                "server_time_field",
                "commit_id",
                "scope",
                "associated_inline_comments",
                "review_thread_join",
            }
            if expected_kind == "unresolved-thread-finding":
                expected_snapshot_keys.update({"thread_id", "thread_resolved"})
            if (
                set(final) != expected_snapshot_keys
                or final.get("complete") is not True
                or final.get("artifact_kind") != expected_kind
                or channel != "pull-request-review"
                or type(artifact_id) is not int
                or artifact_id <= 0
                or type(final.get("stable_artifact_id")) is not int
                or final.get("stable_artifact_id") != artifact_id
                or final.get("url")
                != (
                    f"https://github.com/{repository}/pull/{pr}"
                    f"#pullrequestreview-{artifact_id}"
                )
                or final.get("user_login") != exact_login
                or final.get("user_type") != "Bot"
                or type(server_time) is not int
                or server_time <= 0
                or server_time > history_as_of_server_time
                or type(final.get("submitted_at")) is not int
                or final.get("submitted_at") != server_time
                or final.get("server_time_field") != "submitted_at"
                or final.get("commit_id") != head
                or not typed_json_equal(
                    final.get("scope"),
                    {
                        "repository": repository,
                        "pr": pr,
                        "pr_merge_base": merge_base,
                        "head": head,
                    },
                )
                or not isinstance(body, str)
                or final.get("normalized_body") != body
                or final.get("terminal_looking") is not True
            ):
                return None

            expected_finding = (
                "### 💡 Codex Review\n"
                "- [P1] Fixture finding — "
                f"https://github.com/{repository}/blob/{head}/"
                "src/example.py#L1"
            )
            clean_grammar = (
                outcome == "clean"
                and final.get("state") == "APPROVED"
                and body == "No findings."
                and final.get("grammar_status") == "accepted"
            )
            finding_grammar = (
                outcome == "findings"
                and final.get("state") in {"COMMENTED", "CHANGES_REQUESTED"}
                and body == expected_finding
                and final.get("grammar_status") == "accepted"
            )
            inline_finding_grammar = (
                outcome == "findings"
                and final.get("state") == "COMMENTED"
                and body == ""
                and final.get("grammar_status") == "accepted"
            )
            malformed_grammar = (
                outcome == "malformed"
                and final.get("state") == "APPROVED"
                and body == "Looks good."
                and final.get("grammar_status") == "malformed"
            )
            if expected_kind == "terminal-payload":
                if not (clean_grammar or finding_grammar):
                    return None
            elif expected_kind == "malformed-terminal-artifact":
                if not malformed_grammar:
                    return None
            elif expected_kind == "active-top-level-finding":
                if not finding_grammar:
                    return None
            elif expected_kind == "unresolved-thread-finding":
                child_id = (artifact_id * 10) + 1
                thread_id = f"PRRT_{artifact_id}"
                if (
                    not inline_finding_grammar
                    or final.get("thread_id") != thread_id
                    or final.get("thread_resolved") is not False
                    or not typed_json_equal(
                        final.get("associated_inline_comments"),
                        {
                            "pagination_complete": True,
                            "records": [
                                {
                                    "id": child_id,
                                    "url": (
                                        f"https://github.com/{repository}/pull/{pr}"
                                        f"#discussion_r{child_id}"
                                    ),
                                    "user_login": exact_login,
                                    "user_type": "Bot",
                                    "pull_request_review_id": artifact_id,
                                    "commit_id": head,
                                    "original_commit_id": head,
                                    "body": "[P1] Fixture inline finding",
                                    "normalized_body": "[P1] Fixture inline finding",
                                    "thread_id": thread_id,
                                }
                            ],
                        },
                    )
                    or not typed_json_equal(
                        final.get("review_thread_join"),
                        {
                            "pagination_complete": True,
                            "records": [
                                {
                                    "thread_id": thread_id,
                                    "is_resolved": False,
                                    "comment_ids": [child_id],
                                }
                            ],
                        },
                    )
                ):
                    return None
            else:
                return None
            if expected_kind != "unresolved-thread-finding" and (
                not typed_json_equal(
                    final.get("associated_inline_comments"),
                    {"pagination_complete": True, "records": []},
                )
                or not typed_json_equal(
                    final.get("review_thread_join"),
                    {"pagination_complete": True, "records": []},
                )
            ):
                return None
            return (server_time, artifact_id, expected_kind, outcome, channel)

        def classify_reaction_scope(
            record: dict[str, object],
            *,
            expected_scope: tuple[object, ...] | None = None,
        ) -> str:
            initial_snapshot = record.get("initial_snapshot")
            final_snapshot = record.get("final_snapshot")
            if (
                set(record) != record_fields
                or not isinstance(initial_snapshot, dict)
                or not isinstance(final_snapshot, dict)
                or not typed_json_equal(initial_snapshot, final_snapshot)
                or not typed_json_equal(final_snapshot, record_snapshot(record))
            ):
                return "unknown"
            if record.get("complete") is not True:
                return "unknown"
            if not exact_true_flags(record.get("pagination"), required_pagination):
                return "unknown"
            if not typed_json_equal(record.get("evidence_state"), empty_evidence_state):
                return "unknown"
            record_scope_key = scope_key(record)
            if record_scope_key is None or (
                expected_scope is not None and record_scope_key != expected_scope
            ):
                return "unknown"
            pr = record_scope_key[1]
            raw_requests = record.get("requests")
            raw_reactions = record.get("reactions")
            if (
                not isinstance(raw_requests, list)
                or not raw_requests
                or not isinstance(raw_reactions, list)
            ):
                return "unknown"

            requests_by_id: dict[int, dict[str, object]] = {}
            request_times: dict[int, int] = {}
            for raw_request in raw_requests:
                if (
                    not isinstance(raw_request, dict)
                    or set(raw_request) != request_fields
                ):
                    return "unknown"
                request_id = raw_request.get("id")
                created_at = raw_request.get("created_at")
                updated_at = raw_request.get("updated_at")
                expected_request_time = (
                    created_at if updated_at == created_at else updated_at
                )
                expected_request_time_field = (
                    "created_at" if updated_at == created_at else "updated_at"
                )
                if (
                    type(request_id) is not int
                    or request_id <= 0
                    or request_id in requests_by_id
                    or type(created_at) is not int
                    or type(updated_at) is not int
                    or created_at <= 0
                    or updated_at < created_at
                    or raw_request.get("normalized_body") != "@codex review"
                    or type(raw_request.get("request_server_time")) is not int
                    or raw_request.get("request_server_time") != expected_request_time
                    or raw_request.get("request_server_time_field")
                    != expected_request_time_field
                    or raw_request.get("url")
                    != (
                        f"https://github.com/{current_repository}/pull/{pr}"
                        f"#issuecomment-{request_id}"
                    )
                ):
                    return "unknown"
                requests_by_id[request_id] = raw_request
                request_times[request_id] = expected_request_time

            reactions_by_id: dict[int, dict[str, object]] = {}
            for raw_reaction in raw_reactions:
                if (
                    not isinstance(raw_reaction, dict)
                    or set(raw_reaction) != reaction_fields
                ):
                    return "unknown"
                reaction_id = raw_reaction.get("id")
                if type(reaction_id) is not int or reaction_id <= 0:
                    return "unknown"
                if reaction_id in reactions_by_id:
                    if not typed_json_equal(reactions_by_id[reaction_id], raw_reaction):
                        return "unknown"
                    continue
                reactions_by_id[reaction_id] = raw_reaction

            reactions = list(reactions_by_id.values())
            provider_reactions: list[dict[str, object]] = []
            for item in reactions:
                request_id = item.get("parent_request_id")
                created_at = item.get("created_at")
                reaction_id = item["id"]
                user_login = item.get("user_login")
                user_type = item.get("user_type")
                if (
                    type(request_id) is not int
                    or request_id not in requests_by_id
                    or type(created_at) is not int
                    or created_at <= 0
                    or created_at <= request_times[request_id]
                    or not isinstance(item.get("content"), str)
                    or not item["content"]
                    or not isinstance(user_login, str)
                    or not user_login
                    or not isinstance(user_type, str)
                    or not user_type
                    or item.get("api_url")
                    != (
                        "https://api.github.com/repos/OWNER/REPO/reactions/"
                        f"{reaction_id}"
                    )
                    or item.get("parent_reactions_api_url")
                    != (
                        "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                        f"{request_id}/reactions?per_page=100"
                    )
                ):
                    return "unknown"
                if user_login != exact_login:
                    if user_type == "User" or (
                        user_type == "Bot" and "codex" not in user_login.casefold()
                    ):
                        continue
                    return "unknown"
                if user_type != "Bot" or item["content"] not in ("+1", "eyes"):
                    return "unknown"
                provider_reactions.append(item)

            plus_ones = [item for item in provider_reactions if item["content"] == "+1"]
            if not plus_ones:
                return "unknown"
            selected_plus = max(
                plus_ones,
                key=lambda item: (int(item["created_at"]), int(item["id"])),
            )
            selected_request_id = record.get("selected_request_id")
            selected_reaction_id = record.get("selected_reaction_id")
            if (
                type(selected_request_id) is not int
                or selected_request_id <= 0
                or type(selected_reaction_id) is not int
                or selected_reaction_id <= 0
                or selected_plus["id"] != selected_reaction_id
                or selected_plus["parent_request_id"] != selected_request_id
            ):
                return "unknown"

            latest_request_time = max(request_times.values())
            latest_request_ids = [
                request_id
                for request_id, server_time in request_times.items()
                if server_time == latest_request_time
            ]
            if (
                latest_request_ids != [selected_request_id]
                or int(selected_plus["created_at"]) <= latest_request_time
            ):
                return "unknown"

            selected_order = (
                int(selected_plus["created_at"]),
                int(selected_plus["id"]),
            )
            if any(
                item["content"] == "eyes"
                and (int(item["created_at"]), int(item["id"])) >= selected_order
                for item in provider_reactions
            ):
                return "unknown"
            return "clean"

        def candidate_order_basis(
            record: dict[str, object],
        ) -> tuple[int, int] | None:
            initial_snapshot = record.get("initial_snapshot")
            final_snapshot = record.get("final_snapshot")
            if (
                set(record) != record_fields
                or not isinstance(initial_snapshot, dict)
                or not isinstance(final_snapshot, dict)
                or not typed_json_equal(initial_snapshot, final_snapshot)
                or not typed_json_equal(final_snapshot, record_snapshot(record))
            ):
                return None
            record_scope_key = scope_key(record)
            if (
                record.get("complete") is not True
                or not exact_true_flags(record.get("pagination"), required_pagination)
                or record_scope_key is None
                or not lifecycle_is_typed(record, require_open=False)
            ):
                return None
            evidence_state = record.get("evidence_state")
            if not isinstance(evidence_state, dict):
                return None
            artifact_fields = {
                "terminal_payloads": "terminal-payload",
                "malformed_terminal_artifacts": "malformed-terminal-artifact",
                "active_top_level_findings": "active-top-level-finding",
                "unresolved_thread_findings": "unresolved-thread-finding",
            }
            if set(evidence_state) != set(artifact_fields):
                return None
            artifact_bases: list[tuple[int, int, str, str, str]] = []
            artifacts_by_native_id: dict[tuple[str, int], dict[str, object]] = {}
            artifact_semantics_by_time_id: dict[
                tuple[int, int], tuple[str, str, str]
            ] = {}
            for field, kind in artifact_fields.items():
                artifacts = evidence_state.get(field)
                if not isinstance(artifacts, list):
                    return None
                for artifact in artifacts:
                    validated_artifact = validate_candidate_artifact(
                        artifact,
                        expected_kind=kind,
                        expected_scope=record_scope_key,
                    )
                    if validated_artifact is None:
                        return None
                    (
                        server_time,
                        stable_artifact_id,
                        validated_kind,
                        outcome,
                        channel,
                    ) = validated_artifact
                    native_key = (channel, stable_artifact_id)
                    final_artifact_snapshot = artifact["final_snapshot"]
                    assert isinstance(final_artifact_snapshot, dict)
                    previous_artifact = artifacts_by_native_id.get(native_key)
                    if previous_artifact is not None and not typed_json_equal(
                        previous_artifact, final_artifact_snapshot
                    ):
                        return None
                    semantics_key = (server_time, stable_artifact_id)
                    semantics = (validated_kind, outcome, channel)
                    previous_semantics = artifact_semantics_by_time_id.get(
                        semantics_key
                    )
                    if (
                        previous_semantics is not None
                        and previous_semantics != semantics
                    ):
                        return None
                    if previous_artifact is None:
                        artifacts_by_native_id[native_key] = final_artifact_snapshot
                        artifact_semantics_by_time_id[semantics_key] = semantics
                        artifact_bases.append(validated_artifact)

            pr = record_scope_key[1]
            raw_requests = record.get("requests")
            reactions = record.get("reactions")
            if not isinstance(raw_requests, list) or not isinstance(reactions, list):
                return None

            request_times: dict[int, int] = {}
            for raw_request in raw_requests:
                if (
                    not isinstance(raw_request, dict)
                    or set(raw_request) != request_fields
                ):
                    return None
                request_id = raw_request.get("id")
                created_at = raw_request.get("created_at")
                updated_at = raw_request.get("updated_at")
                expected_request_time = (
                    created_at if updated_at == created_at else updated_at
                )
                expected_request_time_field = (
                    "created_at" if updated_at == created_at else "updated_at"
                )
                if (
                    type(request_id) is not int
                    or request_id <= 0
                    or request_id in request_times
                    or type(created_at) is not int
                    or type(updated_at) is not int
                    or created_at <= 0
                    or updated_at < created_at
                    or created_at > history_as_of_server_time
                    or updated_at > history_as_of_server_time
                    or raw_request.get("normalized_body") != "@codex review"
                    or type(raw_request.get("request_server_time")) is not int
                    or raw_request.get("request_server_time") != expected_request_time
                    or raw_request.get("request_server_time_field")
                    != expected_request_time_field
                    or raw_request.get("url")
                    != (
                        f"https://github.com/{current_repository}/pull/{pr}"
                        f"#issuecomment-{request_id}"
                    )
                ):
                    return None
                request_times[request_id] = expected_request_time

            reactions_by_id: dict[int, dict[str, object]] = {}
            for raw_reaction in reactions:
                if (
                    not isinstance(raw_reaction, dict)
                    or set(raw_reaction) != reaction_fields
                ):
                    return None
                reaction_id = raw_reaction.get("id")
                if type(reaction_id) is not int or reaction_id <= 0:
                    return None
                if reaction_id in reactions_by_id:
                    if not typed_json_equal(reactions_by_id[reaction_id], raw_reaction):
                        return None
                    continue
                reactions_by_id[reaction_id] = raw_reaction

            exact_provider_reactions: list[dict[str, object]] = []
            for item in reactions_by_id.values():
                request_id = item.get("parent_request_id")
                created_at = item.get("created_at")
                reaction_id = item["id"]
                content = item.get("content")
                user_login = item.get("user_login")
                user_type = item.get("user_type")
                if (
                    type(request_id) is not int
                    or request_id not in request_times
                    or type(created_at) is not int
                    or created_at <= 0
                    or created_at <= request_times[request_id]
                    or created_at > history_as_of_server_time
                    or not isinstance(content, str)
                    or not content
                    or item.get("api_url")
                    != (
                        "https://api.github.com/repos/OWNER/REPO/reactions/"
                        f"{reaction_id}"
                    )
                    or item.get("parent_reactions_api_url")
                    != (
                        "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                        f"{request_id}/reactions?per_page=100"
                    )
                ):
                    return None
                confirmed_different_actor = (
                    isinstance(user_login, str)
                    and bool(user_login)
                    and user_login != exact_login
                    and (
                        user_type == "User"
                        or (user_type == "Bot" and "codex" not in user_login.casefold())
                    )
                )
                if confirmed_different_actor:
                    continue
                if (
                    user_login != exact_login
                    or user_type != "Bot"
                    or content not in ("+1", "eyes")
                ):
                    return None
                exact_provider_reactions.append(item)

            plus_ones = [
                item for item in exact_provider_reactions if item["content"] == "+1"
            ]
            selected_request_id = record.get("selected_request_id")
            selected_reaction_id = record.get("selected_reaction_id")
            if plus_ones:
                selected_plus = max(
                    plus_ones,
                    key=lambda item: (int(item["created_at"]), int(item["id"])),
                )
                if (
                    type(selected_request_id) is not int
                    or selected_request_id <= 0
                    or type(selected_reaction_id) is not int
                    or selected_reaction_id <= 0
                    or selected_plus["id"] != selected_reaction_id
                    or selected_plus.get("parent_request_id") != selected_request_id
                ):
                    return None
            elif selected_request_id is not None or selected_reaction_id is not None:
                return None

            if artifact_bases:
                latest_artifact_time = max(item[0] for item in artifact_bases)
                latest_artifacts = [
                    item for item in artifact_bases if item[0] == latest_artifact_time
                ]

                def artifact_precedence(
                    item: tuple[int, int, str, str, str],
                ) -> tuple[int, int]:
                    _, artifact_id, artifact_kind, outcome, _ = item
                    if artifact_kind == "malformed-terminal-artifact":
                        priority = 3
                    elif outcome == "findings":
                        priority = 2
                    else:
                        priority = 1
                    return (priority, artifact_id)

                (
                    server_time,
                    stable_artifact_id,
                    kind,
                    _,
                    _,
                ) = max(latest_artifacts, key=artifact_precedence)
                if any(
                    int(item["created_at"]) >= server_time
                    for item in exact_provider_reactions
                ):
                    return None
            else:
                if not request_times or not exact_provider_reactions:
                    return None
                scope_final_reaction = max(
                    exact_provider_reactions,
                    key=lambda item: (int(item["created_at"]), int(item["id"])),
                )
                latest_request_time = max(request_times.values())
                latest_request_ids = [
                    request_id
                    for request_id, request_time in request_times.items()
                    if request_time == latest_request_time
                ]
                if (
                    len(latest_request_ids) != 1
                    or scope_final_reaction.get("parent_request_id")
                    != latest_request_ids[0]
                    or int(scope_final_reaction["created_at"]) <= latest_request_time
                ):
                    return None
                server_time = scope_final_reaction.get("created_at")
                stable_artifact_id = scope_final_reaction.get("id")
                kind = "reaction"
                if type(server_time) is not int or type(stable_artifact_id) is not int:
                    return None

            expected_basis = {
                "kind": kind,
                "server_time": server_time,
                "stable_artifact_id": stable_artifact_id,
            }
            actual_basis = record.get("candidate_basis")
            if (
                not isinstance(actual_basis, dict)
                or set(actual_basis) != set(expected_basis)
                or not isinstance(actual_basis.get("kind"), str)
                or type(actual_basis.get("server_time")) is not int
                or actual_basis["server_time"] <= 0
                or type(actual_basis.get("stable_artifact_id")) is not int
                or actual_basis["stable_artifact_id"] <= 0
                or not typed_json_equal(actual_basis, expected_basis)
            ):
                return None
            return (server_time, stable_artifact_id)

        def current_lifecycle_is_eligible(record: dict[str, object]) -> bool:
            return lifecycle_is_typed(record, require_open=True)

        def universe_inventory(
            candidates: list[dict[str, object]],
        ) -> dict[str, object]:
            entries: list[dict[str, object]] = []
            for candidate in candidates:
                candidate_scope_key = scope_key(candidate)
                ordering_key = candidate_order_basis(candidate)
                entries.append(
                    {
                        "scope_key": (
                            list(candidate_scope_key)
                            if candidate_scope_key is not None
                            else None
                        ),
                        "candidate_basis": clone(candidate.get("candidate_basis")),
                        "validated_ordering_key": (
                            list(ordering_key) if ordering_key is not None else None
                        ),
                    }
                )
            return {
                "complete": True,
                "repository": current_repository,
                "pagination": clone(required_universe_pagination),
                "entries": entries,
            }

        def history(
            candidates: list[dict[str, object]],
            *,
            complete: bool = True,
        ) -> dict[str, object]:
            inventory = universe_inventory(candidates)
            return {
                "complete": complete,
                "repository": current_repository,
                "as_of_source": "github-response-date-header",
                "as_of_api_url": (
                    f"https://api.github.com/repos/{current_repository}/pulls/"
                    f"{current_pr}"
                ),
                "as_of_server_time": history_as_of_server_time,
                "window_seconds": history_window_seconds,
                "window_start_exclusive": history_start_exclusive,
                "window_end_inclusive": history_as_of_server_time,
                "candidate_universe_count": len(candidates),
                "initial_inventory": clone(inventory),
                "final_inventory": clone(inventory),
                "initial_candidates": clone(candidates),
                "final_candidates": clone(candidates),
            }

        def classify_fallback(
            profile: str,
            provider_declaration: dict[str, object] | None,
            candidate_history: dict[str, object],
            current: dict[str, object],
        ) -> str:
            if profile != "thumbs-up-clean":
                return "not-clean"
            if not declaration_is_authoritative(provider_declaration):
                return "unknown"
            if (
                set(candidate_history)
                != {
                    "complete",
                    "repository",
                    "as_of_source",
                    "as_of_api_url",
                    "as_of_server_time",
                    "window_seconds",
                    "window_start_exclusive",
                    "window_end_inclusive",
                    "candidate_universe_count",
                    "initial_inventory",
                    "final_inventory",
                    "initial_candidates",
                    "final_candidates",
                }
                or candidate_history.get("complete") is not True
                or candidate_history.get("repository") != current_repository
                or candidate_history.get("as_of_source")
                != "github-response-date-header"
                or candidate_history.get("as_of_api_url")
                != (
                    f"https://api.github.com/repos/{current_repository}/pulls/"
                    f"{current_pr}"
                )
                or type(candidate_history.get("as_of_server_time")) is not int
                or candidate_history.get("as_of_server_time")
                != history_as_of_server_time
                or type(candidate_history.get("window_seconds")) is not int
                or candidate_history.get("window_seconds") != history_window_seconds
                or type(candidate_history.get("window_start_exclusive")) is not int
                or candidate_history.get("window_start_exclusive")
                != history_start_exclusive
                or type(candidate_history.get("window_end_inclusive")) is not int
                or candidate_history.get("window_end_inclusive")
                != history_as_of_server_time
            ):
                return "unknown"
            initial_candidates = candidate_history.get("initial_candidates")
            candidates = candidate_history.get("final_candidates")
            initial_inventory = candidate_history.get("initial_inventory")
            final_inventory = candidate_history.get("final_inventory")
            if (
                not isinstance(initial_candidates, list)
                or not isinstance(candidates, list)
                or not typed_json_equal(initial_candidates, candidates)
                or type(candidate_history.get("candidate_universe_count")) is not int
                or candidate_history.get("candidate_universe_count") != len(candidates)
                or not isinstance(initial_inventory, dict)
                or not isinstance(final_inventory, dict)
                or not typed_json_equal(initial_inventory, final_inventory)
                or not typed_json_equal(final_inventory, universe_inventory(candidates))
            ):
                return "unknown"

            ordering_keys: set[tuple[int, int]] = set()
            historical_scope_keys: set[tuple[object, ...]] = set()
            ordered_candidates: list[tuple[tuple[int, int], dict[str, object]]] = []
            global_request_records: dict[int, dict[str, object]] = {}
            global_reaction_records: dict[int, dict[str, object]] = {}
            global_artifact_records: dict[tuple[str, int], dict[str, object]] = {}
            declaration_final = provider_declaration["final_snapshot"]
            assert isinstance(declaration_final, dict)
            declaration_native_id = declaration_final["artifact_id"]
            assert isinstance(declaration_native_id, int)
            global_issue_comment_records: dict[int, dict[str, object]] = {
                declaration_native_id: {
                    "kind": "provider-declaration",
                    "repository": declaration_final["repository"],
                    "pull_request": declaration_final["pull_request"],
                    "api_url": declaration_final["api_url"],
                    "html_url": declaration_final["html_url"],
                    "body": declaration_final["body"],
                }
            }

            def register_global_native_records(
                candidate: dict[str, object],
                candidate_scope_key: tuple[object, ...],
            ) -> bool:
                for raw_request in candidate["requests"]:
                    request_id = raw_request["id"]
                    request_native_record = {
                        "kind": "controlled-request",
                        "repository": candidate_scope_key[0],
                        "pull_request": candidate_scope_key[1],
                        "api_url": (
                            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
                            f"{request_id}"
                        ),
                        "html_url": raw_request["url"],
                        "body": raw_request["normalized_body"],
                    }
                    previous_issue_comment = global_issue_comment_records.get(
                        request_id
                    )
                    if previous_issue_comment is not None and not typed_json_equal(
                        previous_issue_comment, request_native_record
                    ):
                        return False
                    global_issue_comment_records[request_id] = request_native_record
                    record = {
                        "scope_key": list(candidate_scope_key),
                        "record": raw_request,
                    }
                    previous = global_request_records.get(request_id)
                    if previous is not None and not typed_json_equal(previous, record):
                        return False
                    global_request_records[request_id] = record
                for raw_reaction in candidate["reactions"]:
                    reaction_id = raw_reaction["id"]
                    record = {
                        "scope_key": list(candidate_scope_key),
                        "record": raw_reaction,
                    }
                    previous = global_reaction_records.get(reaction_id)
                    if previous is not None and not typed_json_equal(previous, record):
                        return False
                    global_reaction_records[reaction_id] = record
                evidence_state = candidate["evidence_state"]
                for artifacts in evidence_state.values():
                    for artifact in artifacts:
                        final = artifact["final_snapshot"]
                        artifact_key = (final["channel"], final["id"])
                        previous = global_artifact_records.get(artifact_key)
                        if previous is not None and not typed_json_equal(
                            previous, final
                        ):
                            return False
                        global_artifact_records[artifact_key] = final
                return True

            for candidate in candidates:
                if not isinstance(candidate, dict):
                    return "unknown"
                candidate_scope_key = scope_key(candidate)
                ordering_key = candidate_order_basis(candidate)
                if (
                    candidate_scope_key is None
                    or candidate_scope_key == current_scope_key
                    or candidate_scope_key in historical_scope_keys
                    or ordering_key is None
                    or not (
                        history_start_exclusive
                        < ordering_key[0]
                        <= history_as_of_server_time
                    )
                ):
                    return "unknown"
                historical_scope_keys.add(candidate_scope_key)
                if not register_global_native_records(candidate, candidate_scope_key):
                    return "unknown"
                if ordering_key in ordering_keys:
                    return "unknown"
                ordering_keys.add(ordering_key)
                ordered_candidates.append((ordering_key, candidate))

            ordered_candidates.sort(key=lambda item: item[0], reverse=True)
            selected = (
                ordered_candidates[:10]
                if len(ordered_candidates) >= 10
                else ordered_candidates
            )
            if len(selected) < 3:
                return "unknown"
            for _, sample in selected:
                if classify_reaction_scope(sample) != "clean":
                    return "unknown"
            current_ordering_key = candidate_order_basis(current)
            if (
                not current_lifecycle_is_eligible(current)
                or classify_reaction_scope(
                    current,
                    expected_scope=current_scope_key,
                )
                != "clean"
                or current_ordering_key is None
                or current_ordering_key[0] > history_as_of_server_time
                or not register_global_native_records(current, current_scope_key)
            ):
                return "unknown"
            return "clean"

        def sample(pr: int) -> dict[str, object]:
            request_id = 10_000 + pr
            reaction_id = 20_000 + pr
            request_time = 2_000_000 + (pr * 10)
            reaction_time = request_time + 1
            return outcome(
                pr,
                f"{pr:040x}",
                [request(request_id, request_time, pr=pr)],
                [reaction(reaction_id, request_id, reaction_time)],
                selected_request_id=request_id,
                selected_reaction_id=reaction_id,
            )

        def retime_sample(
            record: dict[str, object],
            *,
            request_time: int,
            reaction_time: int,
        ) -> dict[str, object]:
            record["requests"][0]["created_at"] = request_time
            record["requests"][0]["updated_at"] = request_time
            record["requests"][0]["request_server_time"] = request_time
            record["requests"][0]["request_server_time_field"] = "created_at"
            record["reactions"][0]["created_at"] = reaction_time
            record["candidate_basis"]["server_time"] = reaction_time
            return restamp(record)

        samples = [sample(pr) for pr in (2, 3, 4)]
        current = outcome(
            current_pr,
            current_head,
            [request(10, 10, pr=current_pr)],
            [reaction(100, 10, 20)],
            selected_request_id=10,
            selected_reaction_id=100,
            merge_base=current_merge_base,
        )

        thread_scope = scope_key(samples[0])
        assert thread_scope is not None
        valid_thread_artifact = complete_review_artifact(
            samples[0],
            77_001,
            2_700_001,
            artifact_kind="unresolved-thread-finding",
            outcome="findings",
        )
        self.assertIsNotNone(
            validate_candidate_artifact(
                valid_thread_artifact,
                expected_kind="unresolved-thread-finding",
                expected_scope=thread_scope,
            )
        )

        thread_artifact_near_misses: dict[str, dict[str, object]] = {}
        wrong_thread_parent = clone(valid_thread_artifact)
        assert isinstance(wrong_thread_parent, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            wrong_thread_parent[snapshot_name]["associated_inline_comments"]["records"][
                0
            ]["pull_request_review_id"] = 77_002
        thread_artifact_near_misses["wrong-parent-review-id"] = wrong_thread_parent

        wrong_thread_commit = clone(valid_thread_artifact)
        assert isinstance(wrong_thread_commit, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            wrong_thread_commit[snapshot_name]["associated_inline_comments"]["records"][
                0
            ]["commit_id"] = current_head
        thread_artifact_near_misses["wrong-child-commit"] = wrong_thread_commit

        resolved_thread_artifact = clone(valid_thread_artifact)
        assert isinstance(resolved_thread_artifact, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            resolved_thread_artifact[snapshot_name]["thread_resolved"] = True
            resolved_thread_artifact[snapshot_name]["review_thread_join"]["records"][0][
                "is_resolved"
            ] = True
        thread_artifact_near_misses["resolved-thread"] = resolved_thread_artifact

        orphan_thread_join = clone(valid_thread_artifact)
        assert isinstance(orphan_thread_join, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            orphan_thread_join[snapshot_name]["review_thread_join"]["records"][0][
                "comment_ids"
            ] = [999_999]
        thread_artifact_near_misses["orphan-thread-join"] = orphan_thread_join

        numeric_thread_pagination = clone(valid_thread_artifact)
        assert isinstance(numeric_thread_pagination, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            numeric_thread_pagination[snapshot_name]["review_thread_join"][
                "pagination_complete"
            ] = 1
        thread_artifact_near_misses["numeric-pagination"] = numeric_thread_pagination

        for name, artifact in thread_artifact_near_misses.items():
            with self.subTest(unresolved_thread_artifact_near_miss=name):
                self.assertIsNone(
                    validate_candidate_artifact(
                        artifact,
                        expected_kind="unresolved-thread-finding",
                        expected_scope=thread_scope,
                    )
                )

        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(samples),
                current,
            ),
            "clean",
        )
        for profile in ("terminal-payload", "mixed", "unknown"):
            with self.subTest(non_reaction_profile=profile):
                self.assertEqual(
                    classify_fallback(
                        profile,
                        declaration,
                        history(samples),
                        current,
                    ),
                    "not-clean",
                )

        invalid_cases: dict[str, tuple[object, object, object]] = {
            "missing-provider-declaration": (
                None,
                history(samples),
                current,
            ),
            "insufficient-samples": (
                declaration,
                history(samples[:2]),
                current,
            ),
            "incomplete-candidate-universe": (
                declaration,
                history(samples, complete=False),
                current,
            ),
        }
        declaration_drift = clone(declaration)
        assert isinstance(declaration_drift, dict)
        declaration_drift["final_snapshot"]["asserted_text"] = "A changed meaning."
        invalid_cases["provider-declaration-final-reread-drift"] = (
            declaration_drift,
            history(samples),
            current,
        )

        declaration_outer_extension = clone(declaration)
        assert isinstance(declaration_outer_extension, dict)
        declaration_outer_extension["authority_override"] = True
        invalid_cases["provider-declaration-unknown-outer-key"] = (
            declaration_outer_extension,
            history(samples),
            current,
        )

        declaration_snapshot_extension = clone(declaration)
        assert isinstance(declaration_snapshot_extension, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            declaration_snapshot_extension[snapshot_name]["authority_override"] = True
        invalid_cases["provider-declaration-unknown-snapshot-key"] = (
            declaration_snapshot_extension,
            history(samples),
            current,
        )

        declaration_boolean_artifact_id = clone(declaration)
        assert isinstance(declaration_boolean_artifact_id, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            declaration_snapshot = declaration_boolean_artifact_id[snapshot_name]
            declaration_snapshot["artifact_id"] = True
            declaration_snapshot["api_url"] = (
                "https://api.github.com/repos/OWNER/REPO/issues/comments/True"
            )
            declaration_snapshot["html_url"] = (
                "https://github.com/OWNER/REPO/pull/99#issuecomment-True"
            )
        invalid_cases["provider-declaration-boolean-artifact-id"] = (
            declaration_boolean_artifact_id,
            history(samples),
            current,
        )

        untrusted_declaration_url = clone(declaration)
        assert isinstance(untrusted_declaration_url, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            untrusted_declaration_url[snapshot_name]["api_url"] = (
                "https://example.invalid/provider-declaration"
            )
        invalid_cases["provider-declaration-untrusted-url"] = (
            untrusted_declaration_url,
            history(samples),
            current,
        )

        wrong_declaration_actor = clone(declaration)
        assert isinstance(wrong_declaration_actor, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            wrong_declaration_actor[snapshot_name]["user_login"] = "octocat"
        invalid_cases["provider-declaration-wrong-actor"] = (
            wrong_declaration_actor,
            history(samples),
            current,
        )

        local_paraphrase = "A +1 reaction means no findings."
        paraphrased_declaration = clone(declaration)
        assert isinstance(paraphrased_declaration, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            paraphrased_declaration[snapshot_name]["body"] = local_paraphrase
            paraphrased_declaration[snapshot_name]["asserted_text"] = local_paraphrase
            paraphrased_declaration[snapshot_name]["normalized_sha256"] = (
                hashlib.sha256(local_paraphrase.encode("utf-8")).hexdigest()
            )
        invalid_cases["provider-declaration-self-hashed-paraphrase"] = (
            paraphrased_declaration,
            history(samples),
            current,
        )

        wrong_history_source = history(samples)
        wrong_history_source["as_of_source"] = "local-clock"
        invalid_cases["history-untrusted-as-of-source"] = (
            declaration,
            wrong_history_source,
            current,
        )

        extended_history_schema = history(samples)
        extended_history_schema["authority_override"] = True
        invalid_cases["history-unknown-key"] = (
            declaration,
            extended_history_schema,
            current,
        )

        wrong_history_count = history(samples)
        wrong_history_count["candidate_universe_count"] = len(samples) - 1
        invalid_cases["history-universe-count-mismatch"] = (
            declaration,
            wrong_history_count,
            current,
        )

        incomplete_discovery_pagination = history(samples)
        for snapshot_name in ("initial_inventory", "final_inventory"):
            incomplete_discovery_pagination[snapshot_name]["pagination"][
                "pull_requests"
            ] = False
        invalid_cases["history-discovery-pagination-incomplete"] = (
            declaration,
            incomplete_discovery_pagination,
            current,
        )

        discovery_final_reread_drift = history(samples)
        discovery_final_reread_drift["final_inventory"]["pagination"][
            "pull_requests"
        ] = False
        invalid_cases["history-discovery-final-reread-drift"] = (
            declaration,
            discovery_final_reread_drift,
            current,
        )

        truncated_candidate_universe = history([sample(pr) for pr in (2, 3, 4, 5)])
        truncated_candidate_universe["initial_candidates"].pop()
        truncated_candidate_universe["final_candidates"].pop()
        truncated_candidate_universe["candidate_universe_count"] = 3
        invalid_cases["history-truncated-with-synchronized-count"] = (
            declaration,
            truncated_candidate_universe,
            current,
        )

        stale_history_samples = clone(samples)
        assert isinstance(stale_history_samples, list)
        retime_sample(
            stale_history_samples[0],
            request_time=history_start_exclusive - 2,
            reaction_time=history_start_exclusive - 1,
        )
        invalid_cases["history-candidate-before-window"] = (
            declaration,
            history(stale_history_samples),
            current,
        )

        boundary_history_samples = clone(samples)
        assert isinstance(boundary_history_samples, list)
        retime_sample(
            boundary_history_samples[0],
            request_time=history_start_exclusive - 1,
            reaction_time=history_start_exclusive,
        )
        invalid_cases["history-candidate-on-exclusive-boundary"] = (
            declaration,
            history(boundary_history_samples),
            current,
        )

        future_history_samples = clone(samples)
        assert isinstance(future_history_samples, list)
        retime_sample(
            future_history_samples[0],
            request_time=history_as_of_server_time,
            reaction_time=history_as_of_server_time + 1,
        )
        invalid_cases["history-candidate-after-as-of"] = (
            declaration,
            history(future_history_samples),
            current,
        )

        extended_historical_scope = clone(samples)
        assert isinstance(extended_historical_scope, list)
        extended_historical_scope[0]["scope"]["authority_override"] = True
        restamp(extended_historical_scope[0])
        invalid_cases["historical-scope-unknown-key"] = (
            declaration,
            history(extended_historical_scope),
            current,
        )

        future_unrelated_history = clone(samples)
        assert isinstance(future_unrelated_history, list)
        future_history_request_id = future_unrelated_history[0]["selected_request_id"]
        assert isinstance(future_history_request_id, int)
        future_unrelated_history[0]["reactions"].append(
            reaction(
                88_001,
                future_history_request_id,
                history_as_of_server_time + 1,
                content="confused",
                user_login="octocat",
                user_type="User",
            )
        )
        restamp(future_unrelated_history[0])
        invalid_cases["history-unrelated-reaction-after-as-of"] = (
            declaration,
            history(future_unrelated_history),
            current,
        )

        future_current = clone(current)
        assert isinstance(future_current, dict)
        retime_sample(
            future_current,
            request_time=history_as_of_server_time,
            reaction_time=history_as_of_server_time + 1,
        )
        invalid_cases["current-reaction-after-as-of"] = (
            declaration,
            history(samples),
            future_current,
        )

        future_unrelated_current = clone(current)
        assert isinstance(future_unrelated_current, dict)
        future_unrelated_current["reactions"].append(
            reaction(
                88_002,
                10,
                history_as_of_server_time + 1,
                content="confused",
                user_login="octocat",
                user_type="User",
            )
        )
        restamp(future_unrelated_current)
        invalid_cases["current-unrelated-reaction-after-as-of"] = (
            declaration,
            history(samples),
            future_unrelated_current,
        )

        wrong_head = clone(current)
        assert isinstance(wrong_head, dict)
        wrong_head["scope"]["head"] = "f" * 40
        restamp(wrong_head)
        invalid_cases["wrong-current-head"] = (
            declaration,
            history(samples),
            wrong_head,
        )

        wrong_merge_base = clone(current)
        assert isinstance(wrong_merge_base, dict)
        wrong_merge_base["scope"]["pr_merge_base"] = "2" * 40
        restamp(wrong_merge_base)
        invalid_cases["wrong-current-merge-base"] = (
            declaration,
            history(samples),
            wrong_merge_base,
        )

        wrong_repository = clone(current)
        assert isinstance(wrong_repository, dict)
        wrong_repository["scope"]["repository"] = "OWNER/OTHER"
        restamp(wrong_repository)
        invalid_cases["wrong-current-repository"] = (
            declaration,
            history(samples),
            wrong_repository,
        )

        wrong_pr = clone(current)
        assert isinstance(wrong_pr, dict)
        wrong_pr["scope"]["pr"] = 2
        restamp(wrong_pr)
        invalid_cases["wrong-current-pr"] = (
            declaration,
            history(samples),
            wrong_pr,
        )

        extended_current_scope = clone(current)
        assert isinstance(extended_current_scope, dict)
        extended_current_scope["scope"]["authority_override"] = True
        restamp(extended_current_scope)
        invalid_cases["current-scope-unknown-key"] = (
            declaration,
            history(samples),
            extended_current_scope,
        )

        extended_current_schema = clone(current)
        assert isinstance(extended_current_schema, dict)
        extended_current_schema["authority_override"] = True
        invalid_cases["current-unknown-key"] = (
            declaration,
            history(samples),
            extended_current_schema,
        )

        missing_lifecycle = clone(current)
        assert isinstance(missing_lifecycle, dict)
        missing_lifecycle.pop("lifecycle")
        restamp(missing_lifecycle)
        invalid_cases["missing-current-lifecycle"] = (
            declaration,
            history(samples),
            missing_lifecycle,
        )

        closed_lifecycle = clone(current)
        assert isinstance(closed_lifecycle, dict)
        closed_lifecycle["lifecycle"]["state"] = "closed"
        restamp(closed_lifecycle)
        invalid_cases["closed-current-lifecycle"] = (
            declaration,
            history(samples),
            closed_lifecycle,
        )

        merged_lifecycle = clone(current)
        assert isinstance(merged_lifecycle, dict)
        merged_lifecycle["lifecycle"] = {
            "state": "closed",
            "merged": True,
            "merged_at": 40,
        }
        restamp(merged_lifecycle)
        invalid_cases["merged-current-lifecycle"] = (
            declaration,
            history(samples),
            merged_lifecycle,
        )

        lifecycle_final_reread_drift = clone(current)
        assert isinstance(lifecycle_final_reread_drift, dict)
        lifecycle_final_reread_drift["final_snapshot"]["lifecycle"]["state"] = "closed"
        invalid_cases["current-lifecycle-final-reread-drift"] = (
            declaration,
            history(samples),
            lifecycle_final_reread_drift,
        )

        malformed_head = clone(current)
        assert isinstance(malformed_head, dict)
        malformed_head["scope"]["head"] = current_head.upper()
        restamp(malformed_head)
        invalid_cases["non-lowercase-head"] = (
            declaration,
            history(samples),
            malformed_head,
        )

        wrong_request_url = clone(current)
        assert isinstance(wrong_request_url, dict)
        wrong_request_url["requests"][0]["url"] = (
            "https://github.com/OWNER/REPO/pull/2#issuecomment-10"
        )
        restamp(wrong_request_url)
        invalid_cases["wrong-request-url-binding"] = (
            declaration,
            history(samples),
            wrong_request_url,
        )

        extended_request_schema = clone(current)
        assert isinstance(extended_request_schema, dict)
        extended_request_schema["requests"][0]["authority_override"] = True
        restamp(extended_request_schema)
        invalid_cases["request-unknown-key"] = (
            declaration,
            history(samples),
            extended_request_schema,
        )

        missing_request_server_time = clone(current)
        assert isinstance(missing_request_server_time, dict)
        missing_request_server_time["requests"][0].pop("request_server_time")
        restamp(missing_request_server_time)
        invalid_cases["missing-request-server-time"] = (
            declaration,
            history(samples),
            missing_request_server_time,
        )

        wrong_request_server_time_field = clone(current)
        assert isinstance(wrong_request_server_time_field, dict)
        wrong_request_server_time_field["requests"][0]["request_server_time_field"] = (
            "updated_at"
        )
        restamp(wrong_request_server_time_field)
        invalid_cases["wrong-request-server-time-field"] = (
            declaration,
            history(samples),
            wrong_request_server_time_field,
        )

        edited_before_reaction = clone(current)
        assert isinstance(edited_before_reaction, dict)
        edited_before_reaction["requests"][0]["updated_at"] = 30
        edited_before_reaction["requests"][0]["request_server_time"] = 30
        edited_before_reaction["requests"][0]["request_server_time_field"] = (
            "updated_at"
        )
        restamp(edited_before_reaction)
        invalid_cases["reaction-predates-request-edit"] = (
            declaration,
            history(samples),
            edited_before_reaction,
        )

        later_duplicate = clone(current)
        assert isinstance(later_duplicate, dict)
        later_duplicate["requests"].append(request(11, 15, pr=current_pr))
        restamp(later_duplicate)
        invalid_cases["later-duplicate-request"] = (
            declaration,
            history(samples),
            later_duplicate,
        )

        newer_eyes = clone(current)
        assert isinstance(newer_eyes, dict)
        newer_eyes["requests"].append(request(9, 5, pr=current_pr))
        newer_eyes["reactions"].append(reaction(101, 9, 21, content="eyes"))
        restamp(newer_eyes)
        invalid_cases["cross-parent-newer-eyes"] = (
            declaration,
            history(samples),
            newer_eyes,
        )

        conflicting_reaction = clone(current)
        assert isinstance(conflicting_reaction, dict)
        conflicting_reaction["reactions"].append(
            reaction(101, 10, 21, content="confused")
        )
        restamp(conflicting_reaction)
        invalid_cases["conflicting-reaction"] = (
            declaration,
            history(samples),
            conflicting_reaction,
        )

        missing_reaction_id = clone(current)
        assert isinstance(missing_reaction_id, dict)
        missing_reaction_id["reactions"][0]["id"] = None
        restamp(missing_reaction_id)
        invalid_cases["missing-reaction-id"] = (
            declaration,
            history(samples),
            missing_reaction_id,
        )

        wrong_reaction_api_url = clone(current)
        assert isinstance(wrong_reaction_api_url, dict)
        wrong_reaction_api_url["reactions"][0]["api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/reactions/101"
        )
        restamp(wrong_reaction_api_url)
        invalid_cases["wrong-reaction-api-url"] = (
            declaration,
            history(samples),
            wrong_reaction_api_url,
        )

        extended_reaction_schema = clone(current)
        assert isinstance(extended_reaction_schema, dict)
        extended_reaction_schema["reactions"][0]["authority_override"] = True
        restamp(extended_reaction_schema)
        invalid_cases["reaction-unknown-key"] = (
            declaration,
            history(samples),
            extended_reaction_schema,
        )

        wrong_parent_reactions_api_url = clone(current)
        assert isinstance(wrong_parent_reactions_api_url, dict)
        wrong_parent_reactions_api_url["reactions"][0]["parent_reactions_api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
            "11/reactions?per_page=100"
        )
        restamp(wrong_parent_reactions_api_url)
        invalid_cases["wrong-parent-reactions-api-url"] = (
            declaration,
            history(samples),
            wrong_parent_reactions_api_url,
        )

        relocated_reaction = clone(current)
        assert isinstance(relocated_reaction, dict)
        relocated_reaction["requests"].append(request(11, 15, pr=current_pr))
        relocated_reaction["selected_request_id"] = 11
        relocated_reaction["reactions"][0]["parent_request_id"] = 11
        restamp(relocated_reaction)
        invalid_cases["reaction-relocated-with-stale-parent-endpoint"] = (
            declaration,
            history(samples),
            relocated_reaction,
        )

        ambiguous_actor = clone(current)
        assert isinstance(ambiguous_actor, dict)
        ambiguous_actor["reactions"][0]["user_login"] = None
        restamp(ambiguous_actor)
        invalid_cases["ambiguous-reaction-actor"] = (
            declaration,
            history(samples),
            ambiguous_actor,
        )

        exact_login_wrong_type = clone(current)
        assert isinstance(exact_login_wrong_type, dict)
        exact_login_wrong_type["reactions"][0]["user_type"] = "User"
        restamp(exact_login_wrong_type)
        invalid_cases["exact-login-wrong-type"] = (
            declaration,
            history(samples),
            exact_login_wrong_type,
        )

        lookalike_bot = clone(current)
        assert isinstance(lookalike_bot, dict)
        lookalike_bot["reactions"].append(
            reaction(
                101,
                10,
                21,
                content="confused",
                user_login="ChatGPT-Codex-Connector[bot]",
                user_type="Bot",
            )
        )
        restamp(lookalike_bot)
        invalid_cases["lookalike-bot-reaction"] = (
            declaration,
            history(samples),
            lookalike_bot,
        )

        incomplete_current_pagination = clone(current)
        assert isinstance(incomplete_current_pagination, dict)
        incomplete_current_pagination["pagination"]["review_threads"] = False
        restamp(incomplete_current_pagination)
        invalid_cases["incomplete-current-pagination"] = (
            declaration,
            history(samples),
            incomplete_current_pagination,
        )

        numeric_current_pagination = clone(current)
        assert isinstance(numeric_current_pagination, dict)
        numeric_current_pagination["pagination"]["review_threads"] = 1
        restamp(numeric_current_pagination)
        invalid_cases["numeric-current-pagination"] = (
            declaration,
            history(samples),
            numeric_current_pagination,
        )

        numeric_current_lifecycle = clone(current)
        assert isinstance(numeric_current_lifecycle, dict)
        numeric_current_lifecycle["lifecycle"]["merged"] = 0
        restamp(numeric_current_lifecycle)
        invalid_cases["numeric-current-lifecycle"] = (
            declaration,
            history(samples),
            numeric_current_lifecycle,
        )

        boolean_request_id = clone(current)
        assert isinstance(boolean_request_id, dict)
        boolean_request_id["requests"][0]["id"] = True
        boolean_request_id["requests"][0]["url"] = (
            f"https://github.com/{current_repository}/pull/{current_pr}"
            "#issuecomment-True"
        )
        boolean_request_id["reactions"][0]["parent_request_id"] = True
        boolean_request_id["reactions"][0]["parent_reactions_api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
            "True/reactions?per_page=100"
        )
        boolean_request_id["selected_request_id"] = True
        restamp(boolean_request_id)
        invalid_cases["boolean-request-id"] = (
            declaration,
            history(samples),
            boolean_request_id,
        )

        boolean_reaction_id = clone(current)
        assert isinstance(boolean_reaction_id, dict)
        boolean_reaction_id["reactions"][0]["id"] = True
        boolean_reaction_id["reactions"][0]["api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/reactions/True"
        )
        boolean_reaction_id["selected_reaction_id"] = True
        boolean_reaction_id["candidate_basis"]["stable_artifact_id"] = True
        restamp(boolean_reaction_id)
        invalid_cases["boolean-reaction-id"] = (
            declaration,
            history(samples),
            boolean_reaction_id,
        )

        floating_request_time = clone(current)
        assert isinstance(floating_request_time, dict)
        floating_request_time["requests"][0]["created_at"] = 10.0
        floating_request_time["requests"][0]["updated_at"] = 10.0
        floating_request_time["requests"][0]["request_server_time"] = 10.0
        restamp(floating_request_time)
        invalid_cases["floating-request-time"] = (
            declaration,
            history(samples),
            floating_request_time,
        )

        floating_reaction_time = clone(current)
        assert isinstance(floating_reaction_time, dict)
        floating_reaction_time["reactions"][0]["created_at"] = 20.0
        floating_reaction_time["candidate_basis"]["server_time"] = 20.0
        restamp(floating_reaction_time)
        invalid_cases["floating-reaction-time"] = (
            declaration,
            history(samples),
            floating_reaction_time,
        )

        initial_only_numeric_pagination = clone(current)
        assert isinstance(initial_only_numeric_pagination, dict)
        initial_only_numeric_pagination["initial_snapshot"]["pagination"][
            "review_threads"
        ] = 1
        invalid_cases["initial-only-numeric-pagination"] = (
            declaration,
            history(samples),
            initial_only_numeric_pagination,
        )

        for blocker_field in empty_evidence_state:
            blocked_current = clone(current)
            assert isinstance(blocked_current, dict)
            blocked_current["evidence_state"][blocker_field] = ["artifact-1"]
            restamp(blocked_current)
            invalid_cases[f"current-{blocker_field}"] = (
                declaration,
                history(samples),
                blocked_current,
            )

        dismissed_review_blocks_fallback = clone(current)
        assert isinstance(dismissed_review_blocks_fallback, dict)
        dismissed_review_blocks_fallback["evidence_state"][
            "malformed_terminal_artifacts"
        ] = [
            {
                "channel": "review",
                "state": "DISMISSED",
                "body": "No findings.",
            }
        ]
        restamp(dismissed_review_blocks_fallback)
        invalid_cases["dismissed-review-blocks-reaction-fallback"] = (
            declaration,
            history(samples),
            dismissed_review_blocks_fallback,
        )

        current_final_reread_drift = clone(current)
        assert isinstance(current_final_reread_drift, dict)
        current_final_reread_drift["final_snapshot"]["reactions"][0]["content"] = "eyes"
        invalid_cases["current-final-reread-drift"] = (
            declaration,
            history(samples),
            current_final_reread_drift,
        )

        current_in_history = [clone(current), sample(3), sample(4)]
        invalid_cases["current-scope-counted-as-history"] = (
            declaration,
            history(current_in_history),
            current,
        )

        missing_ordering_key = clone(samples)
        assert isinstance(missing_ordering_key, list)
        missing_ordering_key[0]["candidate_basis"]["server_time"] = None
        restamp(missing_ordering_key[0])
        invalid_cases["missing-candidate-ordering-key"] = (
            declaration,
            history(missing_ordering_key),
            current,
        )

        selected_history_blocker = clone(samples)
        assert isinstance(selected_history_blocker, list)
        selected_history_blocker[0]["evidence_state"]["terminal_payloads"] = [
            complete_review_artifact(
                selected_history_blocker[0],
                80_000,
                2_800_000,
            )
        ]
        restamp(selected_history_blocker[0])
        invalid_cases["selected-history-terminal-payload"] = (
            declaration,
            history(selected_history_blocker),
            current,
        )

        history_final_reread_drift = history(samples)
        history_final_reread_drift["final_candidates"][0]["reactions"][0]["content"] = (
            "eyes"
        )
        invalid_cases["history-final-reread-drift"] = (
            declaration,
            history_final_reread_drift,
            current,
        )

        for name, (
            case_declaration,
            case_history,
            case_current,
        ) in invalid_cases.items():
            with self.subTest(reaction_fallback_near_miss=name):
                self.assertEqual(
                    classify_fallback(
                        "thumbs-up-clean",
                        case_declaration,
                        case_history,
                        case_current,
                    ),
                    "unknown",
                )

        first_in_window_samples = clone(samples)
        assert isinstance(first_in_window_samples, list)
        retime_sample(
            first_in_window_samples[0],
            request_time=history_start_exclusive,
            reaction_time=history_start_exclusive + 1,
        )
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(first_in_window_samples),
                current,
            ),
            "clean",
        )

        as_of_boundary_samples = clone(samples)
        assert isinstance(as_of_boundary_samples, list)
        retime_sample(
            as_of_boundary_samples[0],
            request_time=history_as_of_server_time - 1,
            reaction_time=history_as_of_server_time,
        )
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(as_of_boundary_samples),
                current,
            ),
            "clean",
        )

        compatible_earlier_eyes = clone(current)
        assert isinstance(compatible_earlier_eyes, dict)
        compatible_earlier_eyes["requests"].append(request(9, 5, pr=current_pr))
        compatible_earlier_eyes["reactions"].append(reaction(99, 9, 8, content="eyes"))
        restamp(compatible_earlier_eyes)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(samples),
                compatible_earlier_eyes,
            ),
            "clean",
        )

        confirmed_human_reaction = clone(current)
        assert isinstance(confirmed_human_reaction, dict)
        confirmed_human_reaction["reactions"].append(
            reaction(
                101,
                10,
                21,
                content="confused",
                user_login="octocat",
                user_type="User",
            )
        )
        restamp(confirmed_human_reaction)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(samples),
                confirmed_human_reaction,
            ),
            "clean",
        )

        confirmed_unrelated_bot_reaction = clone(current)
        assert isinstance(confirmed_unrelated_bot_reaction, dict)
        confirmed_unrelated_bot_reaction["reactions"].append(
            reaction(
                101,
                10,
                21,
                content="confused",
                user_login="dependabot[bot]",
                user_type="Bot",
            )
        )
        restamp(confirmed_unrelated_bot_reaction)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(samples),
                confirmed_unrelated_bot_reaction,
            ),
            "clean",
        )

        same_pr_different_scope = outcome(
            current_pr,
            "2" * 40,
            [request(12, 2_100_000, pr=current_pr)],
            [reaction(102, 12, 2_100_001)],
            selected_request_id=12,
            selected_reaction_id=102,
            merge_base="3" * 40,
        )
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history([same_pr_different_scope, sample(2), sample(3)]),
                current,
            ),
            "clean",
        )

        for candidate_count in (9, 10, 11):
            with self.subTest(candidate_universe_size=candidate_count):
                candidate_universe = [
                    sample(pr) for pr in range(2, candidate_count + 2)
                ]
                self.assertEqual(
                    classify_fallback(
                        "thumbs-up-clean",
                        declaration,
                        history(candidate_universe),
                        current,
                    ),
                    "clean",
                )

        eleven_candidates = [sample(pr) for pr in range(2, 13)]

        declaration_id_reused_as_request = clone(eleven_candidates)
        assert isinstance(declaration_id_reused_as_request, list)
        declaration_collision_candidate = declaration_id_reused_as_request[0]
        declaration_collision_pr = declaration_collision_candidate["scope"]["pr"]
        declaration_collision_reaction = declaration_collision_candidate["reactions"][0]
        declaration_collision_candidate["requests"][0]["id"] = declaration_artifact_id
        declaration_collision_candidate["requests"][0]["url"] = (
            f"https://github.com/{current_repository}/pull/"
            f"{declaration_collision_pr}#issuecomment-{declaration_artifact_id}"
        )
        declaration_collision_reaction["parent_request_id"] = declaration_artifact_id
        declaration_collision_reaction["parent_reactions_api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
            f"{declaration_artifact_id}/reactions?per_page=100"
        )
        declaration_collision_candidate["selected_request_id"] = declaration_artifact_id
        restamp(declaration_collision_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(declaration_id_reused_as_request),
                current,
            ),
            "unknown",
        )

        cross_scope_request_id_reuse = clone(eleven_candidates)
        assert isinstance(cross_scope_request_id_reuse, list)
        first_request_id = cross_scope_request_id_reuse[0]["requests"][0]["id"]
        request_collision_candidate = cross_scope_request_id_reuse[1]
        request_collision_pr = request_collision_candidate["scope"]["pr"]
        request_collision_candidate["requests"][0]["id"] = first_request_id
        request_collision_candidate["requests"][0]["url"] = (
            f"https://github.com/{current_repository}/pull/"
            f"{request_collision_pr}#issuecomment-{first_request_id}"
        )
        request_collision_candidate["reactions"][0]["parent_request_id"] = (
            first_request_id
        )
        request_collision_candidate["reactions"][0]["parent_reactions_api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
            f"{first_request_id}/reactions?per_page=100"
        )
        request_collision_candidate["selected_request_id"] = first_request_id
        restamp(request_collision_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(cross_scope_request_id_reuse),
                current,
            ),
            "unknown",
        )

        cross_scope_reaction_id_reuse = clone(eleven_candidates)
        assert isinstance(cross_scope_reaction_id_reuse, list)
        first_reaction_id = cross_scope_reaction_id_reuse[0]["reactions"][0]["id"]
        reaction_collision_candidate = cross_scope_reaction_id_reuse[1]
        reaction_collision_candidate["reactions"][0]["id"] = first_reaction_id
        reaction_collision_candidate["reactions"][0]["api_url"] = (
            f"https://api.github.com/repos/OWNER/REPO/reactions/{first_reaction_id}"
        )
        reaction_collision_candidate["selected_reaction_id"] = first_reaction_id
        reaction_collision_candidate["candidate_basis"]["stable_artifact_id"] = (
            first_reaction_id
        )
        restamp(reaction_collision_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(cross_scope_reaction_id_reuse),
                current,
            ),
            "unknown",
        )

        current_history_request_id_reuse = clone(current)
        assert isinstance(current_history_request_id_reuse, dict)
        historical_request_id = eleven_candidates[0]["requests"][0]["id"]
        current_history_request_id_reuse["requests"][0]["id"] = historical_request_id
        current_history_request_id_reuse["requests"][0]["url"] = (
            f"https://github.com/{current_repository}/pull/{current_pr}"
            f"#issuecomment-{historical_request_id}"
        )
        current_history_request_id_reuse["reactions"][0]["parent_request_id"] = (
            historical_request_id
        )
        current_history_request_id_reuse["reactions"][0]["parent_reactions_api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/issues/comments/"
            f"{historical_request_id}/reactions?per_page=100"
        )
        current_history_request_id_reuse["selected_request_id"] = historical_request_id
        restamp(current_history_request_id_reuse)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(eleven_candidates),
                current_history_request_id_reuse,
            ),
            "unknown",
        )

        current_history_reaction_id_reuse = clone(current)
        assert isinstance(current_history_reaction_id_reuse, dict)
        historical_reaction_id = eleven_candidates[0]["reactions"][0]["id"]
        current_history_reaction_id_reuse["reactions"][0]["id"] = historical_reaction_id
        current_history_reaction_id_reuse["reactions"][0]["api_url"] = (
            "https://api.github.com/repos/OWNER/REPO/reactions/"
            f"{historical_reaction_id}"
        )
        current_history_reaction_id_reuse["selected_reaction_id"] = (
            historical_reaction_id
        )
        current_history_reaction_id_reuse["candidate_basis"]["stable_artifact_id"] = (
            historical_reaction_id
        )
        restamp(current_history_reaction_id_reuse)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(eleven_candidates),
                current_history_reaction_id_reuse,
            ),
            "unknown",
        )

        unselected_stale_selected_provenance = clone(eleven_candidates)
        assert isinstance(unselected_stale_selected_provenance, list)
        oldest_provenance_candidate = unselected_stale_selected_provenance[0]
        oldest_provenance_pr = oldest_provenance_candidate["scope"]["pr"]
        earlier_request_id = 71_001
        earlier_reaction_id = 72_001
        earlier_request_time = (
            oldest_provenance_candidate["requests"][0]["created_at"] - 2
        )
        earlier_reaction_time = earlier_request_time + 1
        oldest_provenance_candidate["requests"].append(
            request(
                earlier_request_id,
                earlier_request_time,
                pr=oldest_provenance_pr,
            )
        )
        oldest_provenance_candidate["reactions"].append(
            reaction(
                earlier_reaction_id,
                earlier_request_id,
                earlier_reaction_time,
            )
        )
        oldest_provenance_candidate["selected_request_id"] = earlier_request_id
        oldest_provenance_candidate["selected_reaction_id"] = earlier_reaction_id
        oldest_provenance_candidate["candidate_basis"] = {
            "kind": "reaction",
            "server_time": earlier_reaction_time,
            "stable_artifact_id": earlier_reaction_id,
        }
        restamp(oldest_provenance_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_stale_selected_provenance),
                current,
            ),
            "unknown",
        )

        cross_scope_artifact_id_reuse = [sample(pr) for pr in range(2, 14)]
        assert isinstance(cross_scope_artifact_id_reuse, list)
        for index in (0, 1):
            artifact_collision_candidate = cross_scope_artifact_id_reuse[index]
            terminal_time = (
                artifact_collision_candidate["reactions"][0]["created_at"] + 1
            )
            artifact_collision_candidate["evidence_state"]["terminal_payloads"] = [
                complete_review_artifact(
                    artifact_collision_candidate,
                    73_001,
                    terminal_time,
                )
            ]
            artifact_collision_candidate["candidate_basis"] = {
                "kind": "terminal-payload",
                "server_time": terminal_time,
                "stable_artifact_id": 73_001,
            }
            restamp(artifact_collision_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(cross_scope_artifact_id_reuse),
                current,
            ),
            "unknown",
        )

        unselected_negative_request_reaction_times = clone(eleven_candidates)
        assert isinstance(unselected_negative_request_reaction_times, list)
        negative_time_candidate = unselected_negative_request_reaction_times[0]
        negative_time_candidate["requests"][0]["created_at"] = -2
        negative_time_candidate["requests"][0]["updated_at"] = -2
        negative_time_candidate["requests"][0]["request_server_time"] = -2
        negative_time_candidate["reactions"][0]["created_at"] = -1
        low_terminal_time = history_start_exclusive + 1
        negative_time_candidate["evidence_state"]["terminal_payloads"] = [
            complete_review_artifact(
                negative_time_candidate,
                74_001,
                low_terminal_time,
            )
        ]
        negative_time_candidate["candidate_basis"] = {
            "kind": "terminal-payload",
            "server_time": low_terminal_time,
            "stable_artifact_id": 74_001,
        }
        restamp(negative_time_candidate)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_negative_request_reaction_times),
                current,
            ),
            "unknown",
        )

        terminal_payload_changes_candidate_order = clone(eleven_candidates)
        assert isinstance(terminal_payload_changes_candidate_order, list)
        terminal_payload_changes_candidate_order[0]["evidence_state"][
            "terminal_payloads"
        ] = [
            complete_review_artifact(
                terminal_payload_changes_candidate_order[0],
                99_999,
                2_900_000,
            )
        ]
        terminal_payload_changes_candidate_order[0]["candidate_basis"] = {
            "kind": "terminal-payload",
            "server_time": 2_900_000,
            "stable_artifact_id": 99_999,
        }
        restamp(terminal_payload_changes_candidate_order[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(terminal_payload_changes_candidate_order),
                current,
            ),
            "unknown",
        )

        def history_with_unselected_terminal_basis() -> list[dict[str, object]]:
            candidates = clone(eleven_candidates)
            assert isinstance(candidates, list)
            oldest = candidates[0]
            terminal_time = int(oldest["reactions"][0]["created_at"]) + 1
            oldest["evidence_state"]["terminal_payloads"] = [
                complete_review_artifact(oldest, 90_000, terminal_time)
            ]
            oldest["candidate_basis"] = {
                "kind": "terminal-payload",
                "server_time": terminal_time,
                "stable_artifact_id": 90_000,
            }
            restamp(oldest)
            return candidates

        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(history_with_unselected_terminal_basis()),
                current,
            ),
            "clean",
        )

        def assert_unselected_artifact_history_rejected(
            candidates: list[dict[str, object]],
        ) -> None:
            self.assertEqual(
                classify_fallback(
                    "thumbs-up-clean",
                    declaration,
                    history(candidates),
                    current,
                ),
                "unknown",
            )

        history_with_unknown_evidence_channel = clone(eleven_candidates)
        assert isinstance(history_with_unknown_evidence_channel, list)
        oldest = history_with_unknown_evidence_channel[0]
        oldest["evidence_state"]["unknown_terminal_artifacts"] = []
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            history_with_unknown_evidence_channel
        )

        history_with_conflicting_native_artifact = clone(eleven_candidates)
        assert isinstance(history_with_conflicting_native_artifact, list)
        oldest = history_with_conflicting_native_artifact[0]
        terminal_time = int(oldest["reactions"][0]["created_at"]) + 1
        commented_finding = complete_review_artifact(
            oldest,
            90_010,
            terminal_time,
            outcome="findings",
        )
        changes_requested_finding = clone(commented_finding)
        assert isinstance(changes_requested_finding, dict)
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            changes_requested_finding[snapshot_name]["state"] = "CHANGES_REQUESTED"
        oldest["evidence_state"]["terminal_payloads"] = [
            commented_finding,
            changes_requested_finding,
        ]
        oldest["candidate_basis"] = {
            "kind": "terminal-payload",
            "server_time": terminal_time,
            "stable_artifact_id": 90_010,
        }
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            history_with_conflicting_native_artifact
        )

        history_with_wrong_finding_subtype_precedence = clone(eleven_candidates)
        assert isinstance(history_with_wrong_finding_subtype_precedence, list)
        oldest = history_with_wrong_finding_subtype_precedence[0]
        boundary_time = eleven_candidates[1]["candidate_basis"]["server_time"]
        assert isinstance(boundary_time, int)
        oldest["evidence_state"]["active_top_level_findings"] = [
            complete_review_artifact(
                oldest,
                90_000,
                boundary_time,
                artifact_kind="active-top-level-finding",
                outcome="findings",
            )
        ]
        oldest["evidence_state"]["unresolved_thread_findings"] = [
            complete_review_artifact(
                oldest,
                10_000,
                boundary_time,
                artifact_kind="unresolved-thread-finding",
                outcome="findings",
            )
        ]
        oldest["candidate_basis"] = {
            "kind": "unresolved-thread-finding",
            "server_time": boundary_time,
            "stable_artifact_id": 10_000,
        }
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            history_with_wrong_finding_subtype_precedence
        )

        terminal_basis_with_sparse_artifact = history_with_unselected_terminal_basis()
        oldest = terminal_basis_with_sparse_artifact[0]
        terminal_time = oldest["candidate_basis"]["server_time"]
        oldest["evidence_state"]["terminal_payloads"] = [
            {
                "server_time": terminal_time,
                "stable_artifact_id": 90_000,
            }
        ]
        restamp(oldest)
        assert_unselected_artifact_history_rejected(terminal_basis_with_sparse_artifact)

        terminal_basis_with_lookalike_artifact = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_lookalike_artifact[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact[snapshot_name]["user_login"] = "codex-review-helper[bot]"
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_lookalike_artifact
        )

        terminal_basis_without_submitted_at = history_with_unselected_terminal_basis()
        oldest = terminal_basis_without_submitted_at[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            del artifact[snapshot_name]["submitted_at"]
        restamp(oldest)
        assert_unselected_artifact_history_rejected(terminal_basis_without_submitted_at)

        terminal_basis_with_mismatched_submitted_at = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_mismatched_submitted_at[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact[snapshot_name]["submitted_at"] += 1
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_mismatched_submitted_at
        )

        terminal_basis_with_future_submitted_at = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_future_submitted_at[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact[snapshot_name]["submitted_at"] = history_as_of_server_time + 1
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_future_submitted_at
        )

        terminal_basis_with_incomplete_artifact_page = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_incomplete_artifact_page[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact[snapshot_name]["associated_inline_comments"][
                "pagination_complete"
            ] = False
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_incomplete_artifact_page
        )

        terminal_basis_with_scope_conflict = history_with_unselected_terminal_basis()
        oldest = terminal_basis_with_scope_conflict[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        for snapshot_name in ("initial_snapshot", "final_snapshot"):
            artifact[snapshot_name]["scope"]["head"] = "f" * 40
        restamp(oldest)
        assert_unselected_artifact_history_rejected(terminal_basis_with_scope_conflict)

        terminal_basis_with_artifact_reread_drift = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_artifact_reread_drift[0]
        artifact = oldest["evidence_state"]["terminal_payloads"][0]
        artifact["final_snapshot"]["body"] = "No findings. "
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_artifact_reread_drift
        )

        terminal_basis_with_same_id_conflict = history_with_unselected_terminal_basis()
        oldest = terminal_basis_with_same_id_conflict[0]
        terminal_time = oldest["candidate_basis"]["server_time"]
        assert isinstance(terminal_time, int)
        oldest["evidence_state"]["active_top_level_findings"] = [
            complete_review_artifact(
                oldest,
                90_000,
                terminal_time,
                artifact_kind="active-top-level-finding",
                outcome="findings",
            )
        ]
        oldest["candidate_basis"]["kind"] = "active-top-level-finding"
        restamp(oldest)
        assert_unselected_artifact_history_rejected(
            terminal_basis_with_same_id_conflict
        )

        for later_content in ("eyes", "+1"):
            with self.subTest(
                unselected_artifact_basis_with_later_reaction=later_content
            ):
                artifact_basis_with_later_reaction = (
                    history_with_unselected_terminal_basis()
                )
                oldest = artifact_basis_with_later_reaction[0]
                request_id = oldest["selected_request_id"]
                assert isinstance(request_id, int)
                oldest["reactions"].append(
                    reaction(
                        90_003,
                        request_id,
                        2_900_000,
                        content=later_content,
                    )
                )
                restamp(oldest)
                assert_unselected_artifact_history_rejected(
                    artifact_basis_with_later_reaction
                )

        terminal_basis_with_future_human = history_with_unselected_terminal_basis()
        oldest = terminal_basis_with_future_human[0]
        request_id = oldest["selected_request_id"]
        assert isinstance(request_id, int)
        oldest["reactions"].append(
            reaction(
                90_001,
                request_id,
                history_as_of_server_time + 1,
                content="confused",
                user_login="human-reviewer",
                user_type="User",
            )
        )
        restamp(oldest)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(terminal_basis_with_future_human),
                current,
            ),
            "unknown",
        )

        terminal_basis_with_relocated_reaction = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_relocated_reaction[0]
        original_request = oldest["requests"][0]
        original_request_time = original_request["request_server_time"]
        assert isinstance(original_request_time, int)
        oldest["requests"].append(request(90_002, original_request_time - 1, pr=2))
        oldest["reactions"][0]["parent_request_id"] = 90_002
        restamp(oldest)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(terminal_basis_with_relocated_reaction),
                current,
            ),
            "unknown",
        )

        terminal_basis_with_ambiguous_reaction = (
            history_with_unselected_terminal_basis()
        )
        oldest = terminal_basis_with_ambiguous_reaction[0]
        oldest["reactions"][0]["user_type"] = None
        restamp(oldest)
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(terminal_basis_with_ambiguous_reaction),
                current,
            ),
            "unknown",
        )

        unselected_final_reread_drift = clone(eleven_candidates)
        assert isinstance(unselected_final_reread_drift, list)
        unselected_final_reread_drift[0]["final_snapshot"]["reactions"][0][
            "created_at"
        ] = 2_900_000
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_final_reread_drift),
                current,
            ),
            "unknown",
        )

        unselected_incomplete_pagination = clone(eleven_candidates)
        assert isinstance(unselected_incomplete_pagination, list)
        unselected_incomplete_pagination[0]["pagination"]["reviews"] = False
        restamp(unselected_incomplete_pagination[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_incomplete_pagination),
                current,
            ),
            "unknown",
        )

        unselected_newer_eyes = clone(eleven_candidates)
        assert isinstance(unselected_newer_eyes, list)
        unselected_request_id = unselected_newer_eyes[0]["selected_request_id"]
        assert isinstance(unselected_request_id, int)
        unselected_newer_eyes[0]["reactions"].append(
            reaction(
                99_999,
                unselected_request_id,
                2_900_000,
                content="eyes",
            )
        )
        restamp(unselected_newer_eyes[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_newer_eyes),
                current,
            ),
            "unknown",
        )

        invalid_oldest_unselected = clone(eleven_candidates)
        assert isinstance(invalid_oldest_unselected, list)
        invalid_oldest_unselected[0]["reactions"][0]["user_type"] = "User"
        restamp(invalid_oldest_unselected[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(invalid_oldest_unselected),
                current,
            ),
            "unknown",
        )

        unselected_lookalike_bot = clone(eleven_candidates)
        assert isinstance(unselected_lookalike_bot, list)
        unselected_lookalike_bot[0]["reactions"][0]["user_login"] = (
            "codex-review-helper[bot]"
        )
        restamp(unselected_lookalike_bot[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_lookalike_bot),
                current,
            ),
            "unknown",
        )

        unselected_missing_type = clone(eleven_candidates)
        assert isinstance(unselected_missing_type, list)
        unselected_missing_type[0]["reactions"][0]["user_type"] = None
        restamp(unselected_missing_type[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_missing_type),
                current,
            ),
            "unknown",
        )

        unselected_conflicting_content = clone(eleven_candidates)
        assert isinstance(unselected_conflicting_content, list)
        unselected_conflicting_content[0]["reactions"][0]["content"] = "confused"
        restamp(unselected_conflicting_content[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(unselected_conflicting_content),
                current,
            ),
            "unknown",
        )

        invalid_newest_selected = clone(eleven_candidates)
        assert isinstance(invalid_newest_selected, list)
        invalid_newest_selected[-1]["reactions"][0]["user_type"] = "User"
        restamp(invalid_newest_selected[-1])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(invalid_newest_selected),
                current,
            ),
            "unknown",
        )

        invalid_tenth_newest_selected = clone(eleven_candidates)
        assert isinstance(invalid_tenth_newest_selected, list)
        invalid_tenth_newest_selected[1]["reactions"][0]["user_type"] = "User"
        restamp(invalid_tenth_newest_selected[1])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(invalid_tenth_newest_selected),
                current,
            ),
            "unknown",
        )

        ten_candidates = [sample(pr) for pr in range(2, 12)]
        invalid_oldest_of_exact_ten = clone(ten_candidates)
        assert isinstance(invalid_oldest_of_exact_ten, list)
        invalid_oldest_of_exact_ten[0]["reactions"][0]["user_type"] = "User"
        restamp(invalid_oldest_of_exact_ten[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(invalid_oldest_of_exact_ten),
                current,
            ),
            "unknown",
        )

        nine_candidates = [sample(pr) for pr in range(2, 11)]
        invalid_oldest_selected = clone(nine_candidates)
        assert isinstance(invalid_oldest_selected, list)
        invalid_oldest_selected[0]["reactions"][0]["user_type"] = "User"
        restamp(invalid_oldest_selected[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(invalid_oldest_selected),
                current,
            ),
            "unknown",
        )

        missing_unselected_order_key = clone(eleven_candidates)
        assert isinstance(missing_unselected_order_key, list)
        missing_unselected_order_key[0]["candidate_basis"]["stable_artifact_id"] = None
        restamp(missing_unselected_order_key[0])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(missing_unselected_order_key),
                current,
            ),
            "unknown",
        )

        forged_unselected_order_key = clone(eleven_candidates)
        assert isinstance(forged_unselected_order_key, list)
        forged_unselected_order_key[-1]["candidate_basis"]["server_time"] = 1
        restamp(forged_unselected_order_key[-1])
        self.assertEqual(
            classify_fallback(
                "thumbs-up-clean",
                declaration,
                history(forged_unselected_order_key),
                current,
            ),
            "unknown",
        )

        normalized_authority = " ".join(authority.split()).lower()
        for anchor in (
            "belong to the unique accepted request with the greatest request "
            "semantic time",
            "equal-time latest requests are ambiguous",
            "every accepted same-scope controlled request parent",
            "single selected parent's reaction page cannot prove",
            "historical candidates exclude the exact current scope",
            "`candidate_basis.server_time`",
            "a reaction supplies this basis only when",
            "validate the basis against the complete scope evidence for every candidate",
            "confirmed different actor",
            "`codex`-containing bot login",
            "provider-like identity ambiguity",
            "identical initial/final discovery inventories",
            "a bare `complete: true` and a caller-adjustable count",
            "removing a candidate while decrementing the count",
            "including confirmed-different-actor reactions",
            "its payload kind does not itself select the provider profile",
            "unknown fields and json type aliases are not forward-compatible",
            "historical_universe",
            "initial_candidates",
            "final_candidates",
            "current.initial_snapshot",
            "state: open",
            "merged: false",
            "merged_at: null",
            "same_scope_request_audit",
            "`parent_request_id`",
            "`parent_reactions_api_url`",
            "relocating an r1 reaction under r2",
        ):
            self.assertIn(anchor, normalized_authority)

    def test_named_lanes_materialize_before_the_first_status_query(self) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        claude = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        reviewer = (policy_scope_root / "agents/reviewer.toml").read_text(
            encoding="utf-8"
        )
        repository_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        delivery = (
            policy_scope_root / "skills/change-delivery-workflow/SKILL.md"
        ).read_text(encoding="utf-8")

        documents = {
            "skill": skill,
            "lane contracts": contracts,
            "Claude lane": claude,
            "prompt templates": templates,
            "PR readiness": readiness,
            "reviewer profile": reviewer,
            "repository policy": repository_policy,
            "delivery entrypoint": delivery,
        }
        if CI_PROFILE == "canonical":
            documents["README"] = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

        for name, content in documents.items():
            with self.subTest(document=name):
                self.assertIn("materialize-worktree", content)
                self.assertIn("validate-worktree", content)

        shared = contracts[
            contracts.index("## Shared Frozen-Range Contract") : contracts.index(
                "## Separate PR/Master Secret Admission"
            )
        ]
        ordered_anchors = (
            "pre-status isolated reachable-object import",
            "Before checkout",
            "Materialize `head_sha` only after that audit",
            "As the first worktree-status operation",
            "Codex spawn or Claude process launch",
        )
        positions = tuple(shared.index(anchor) for anchor in ordered_anchors)
        self.assertEqual(positions, tuple(sorted(positions)))

        for anchor in (
            "version 2.45.0 or newer",
            "`/usr/bin/env -i`",
            "`GIT_CONFIG_NOSYSTEM=1`",
            "`GIT_CONFIG_GLOBAL=/dev/null`",
            "`GIT_CONFIG_SYSTEM=/dev/null`",
            "`GIT_ATTR_NOSYSTEM=1`",
            "`GIT_CEILING_DIRECTORIES=<destination-parent>`",
            "`GIT_NO_LAZY_FETCH=1`",
            "`GIT_NO_REPLACE_OBJECTS=1`",
            "`GIT_TERMINAL_PROMPT=0`",
            "-c core.hooksPath=<empty-private-hooks>",
            "-c core.commitGraph=false",
            "-c core.multiPackIndex=false",
            "-c core.fsmonitor=false",
            "-c core.attributesFile=/dev/null",
            "-c submodule.recurse=false",
            "250,000 reachable objects",
            "2 GiB of reachable logical object bytes",
            "256 MiB compressed pack",
            "pack-objects --stdout --no-reuse-delta --no-reuse-object",
            "index-pack --stdin --strict --max-input-size=<256 MiB>",
            "destination's complete object inventory",
            "promisor markers/configuration",
            "sibling `.bundle` / `.git` suffix discovery",
            "exact `.git` marker",
            "bounded full object-validity `git fsck`",
            "no `commondir`, `config.worktree`, per-worktree config",
            "alternate, HTTP-alternate, shallow, sparse, promisor, or pack `.bitmap` state",
            "executable clean/smudge/process filter",
            "The guard's forced ordinary/staged status is the first status query",
            "recorded device, inode, and owner",
        ):
            self.assertIn(anchor, shared)

        self.assertIn("never use `git worktree add`", shared)
        self.assertIn("never loaded by Git", shared)
        self.assertIn("cleanup failure must report the exact retained path", skill)
        self.assertIn("complete flushed success receipt", skill)
        self.assertNotIn("parent-validated native Git", shared)
        self.assertIn("prior-policy bootstrap", templates)
        self.assertNotIn(
            "Before launch, require `git status --porcelain`",
            contracts,
        )

    def test_named_lane_source_marker_bitmap_and_path_envelope_contracts(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        self.assertIn("device, inode, file type, and owner", skill)
        self.assertIn("(st_dev, st_ino, file type, st_uid)", contracts)
        self.assertIn("device/inode/type/owner", canonical)
        for content in (skill, contracts, canonical):
            for anchor in (
                "forward `gitdir:` target",
                "back-pointer",
                "`mtime`",
                "`ctime`",
                "`nlink`",
                "benign churn",
                "source pack `.bitmap`",
                "--no-use-bitmap-index",
                "100,000",
                "64 MiB",
                "SHA-1",
                "SHA-256",
                "`ls-tree`",
                "`ls-files`",
                "`status`",
            ):
                with self.subTest(anchor=anchor):
                    self.assertIn(anchor, content)
        self.assertIn("producer-output bound", contracts)
        self.assertIn("not a claim", contracts)
        self.assertIn("producer-output bound", canonical)

        marker_binding = runtime.split("class _MaterializerSourceMarkerBinding:", 1)[
            1
        ].split("@dataclass", 1)[0]
        for field in ("device", "inode", "file_type", "owner", "is_gitfile"):
            self.assertIn(f"{field}:", marker_binding)
        for excluded in ("mtime", "ctime", "nlink", "digest"):
            self.assertNotIn(excluded, marker_binding)
        self.assertIn("_read_materializer_gitfile_admin(binding.path, source)", runtime)
        self.assertIn('label="Git admin back-pointer"', runtime)
        self.assertIn("if back_pointer != marker:", runtime)
        self.assertIn('| getattr(os, "O_NONBLOCK", 0)', runtime)
        self.assertIn(
            "_verify_materializer_source_back_pointer(storage.marker, storage.admin)",
            runtime,
        )
        self.assertIn('folded_name.endswith(".bitmap")', runtime)
        self.assertIn('"--no-use-bitmap-index"', runtime)
        self.assertIn(
            "return MATERIALIZER_CHECKOUT_PATH_BYTES_LIMIT + (",
            runtime,
        )
        self.assertIn(
            "MATERIALIZER_CHECKOUT_ENTRY_COUNT_LIMIT * (oid_length + 16)",
            runtime,
        )
        self.assertEqual(
            runtime.count("_checkout_tree_output_limit(len(frozen_head))"),
            4,
        )
        self.assertIn("output_limit = _checkout_tree_output_limit(oid_length)", runtime)

        if CI_PROFILE == "canonical":
            journal = (
                REPO_ROOT
                / "docs/project_journal/2026/07/"
                / "2026-07-21-named-lane-review-guards-rpf001.md"
            ).read_text(encoding="utf-8")
            for anchor in (
                "forward `gitdir:` target",
                "`nlink`",
                "--no-use-bitmap-index",
                "100,000-entry",
                "SHA-1 or SHA-256",
            ):
                self.assertIn(anchor, journal)

    def test_review_scope_and_github_provider_identity_are_fail_closed(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        egress = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        delivery = (
            _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
            / "skills/change-delivery-workflow/SKILL.md"
        ).read_text(encoding="utf-8")
        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        normalized_authority = " ".join(authority.split()).lower()

        for content in (skill, readiness, probes, contracts, agents_policy, interface):
            self.assertIn("blocked-input", content)
            self.assertIn("explicit", content)
            self.assertIn("target", content)
        for content in (skill, readiness, probes, contracts):
            self.assertIn("exact current head repository/branch", content)
            self.assertIn("no-PR", content)
            self.assertIn("explicit committed range", content)
            self.assertIn("explicitly named target/base", content)
            self.assertIn("blocked-authorization", content)
        self.assertIn(
            "More than one required PR candidate leaves the GitHub/PR-specific lane `blocked-input` until the caller names a PR",
            skill,
        )
        self.assertIn(
            "An authenticated successful lookup returning `[]` proves the no-PR path",
            probes,
        )
        for content in (readiness, probes, contracts):
            self.assertIn(
                "Explicit-range-only standalone single/double",
                content,
            )
            self.assertIn("no PR probe", content)
            self.assertIn("A frozen range", content)
            self.assertIn("never selects a PR", content)
            self.assertIn("required explicit PR selector is absent", content)
            self.assertIn("local lanes may still run", content.lower())
        self.assertNotIn("require an explicit PR or frozen range", readiness)
        self.assertNotIn("supplies an explicit PR or frozen range", probes)
        self.assertIn(
            "an existing frozen range allows only the local lanes to run; the GitHub/PR-specific lane remains `blocked-input` until the caller names the PR",
            readiness,
        )
        self.assertIn(
            "a frozen range does not cure that ambiguity",
            probes,
        )
        self.assertIn(
            "report the GitHub lane `blocked-input` and the overall shape `requested: triple`, `effective: triple-inconclusive`",
            readiness,
        )
        self.assertIn("--method GET --paginate --slurp", probes)
        self.assertIn("-f 'head=<head-owner>:<current-branch>'", probes)
        self.assertNotIn(
            "pulls?state=open&head=<head-owner>:<current-branch>",
            probes,
        )

        identity_documents = (
            skill,
            readiness,
            probes,
            contracts,
            templates,
            egress,
            agents_policy,
            interface,
            delivery,
            authority,
        )
        for content in identity_documents:
            self.assertIn("github.com", content)
            self.assertIn("chatgpt-codex-connector[bot]", content)
            self.assertIn("chatgpt-codex-connector", content)
        for content in (
            skill,
            readiness,
            probes,
            contracts,
            templates,
            egress,
            authority,
        ):
            self.assertIn("Bot", content)
        self.assertIn('user.login == "chatgpt-codex-connector[bot]"', probes)
        self.assertIn('user.type == "Bot"', probes)
        self.assertIn('app.slug == "chatgpt-codex-connector"', probes)
        for anchor in (
            "latest trustworthy terminal artifact",
            "fully paginate issue comments, reviews, every associated inline review comment",
            "terminal issue comments or pull-request reviews",
        ):
            self.assertIn(anchor, normalized_authority)
        for content in (
            skill,
            readiness,
            contracts,
            templates,
            egress,
            agents_policy,
            interface,
            delivery,
        ):
            with self.subTest(payload_failure_contract=content[:40]):
                lowered = content.lower()
                self.assertIn("missing", lowered)
                self.assertIn("ambiguous", lowered)
                self.assertIn("triple-inconclusive", lowered)
        for content in (readiness, probes, contracts, authority):
            with self.subTest(liveness_document=content[:40]):
                normalized = " ".join(content.split()).lower().replace("-", " ")
                self.assertTrue(
                    "`eyes` is liveness only" in normalized
                    or "`eyes` proves liveness only" in normalized
                )
        self.assertNotIn("Accept a check/run only when", probes)

        for anchor in (
            "'repos/<owner>/<repo>/pulls/<number>/reviews?per_page=100'",
            "body}]'",
            "'repos/<owner>/<repo>/pulls/<number>/reviews/<review_id>/comments?per_page=100'",
            "pull_request_review_id",
            "'repos/<owner>/<repo>/issues/<number>/comments?per_page=100'",
            "'repos/<owner>/<repo>/issues/comments/<request_comment_id>/reactions?per_page=100'",
            "COMMENTED",
            "APPROVED",
            "CHANGES_REQUESTED",
            "`PENDING` is nonterminal",
        ):
            self.assertIn(anchor, probes)
        self.assertGreaterEqual(probes.count("--method GET --paginate --slurp"), 5)
        reaction_probe = probes.split(
            "'repos/<owner>/<repo>/issues/comments/"
            "<request_comment_id>/reactions?per_page=100'",
            1,
        )[1].split("```", 1)[0]
        for anchor in (
            "--method GET --paginate --slurp",
            "api_url",
            "https://api.github.com/repos/<owner>/<repo>/reactions/",
            ".id",
            ".user.login",
            ".user.type",
            "content",
            "created_at",
        ):
            self.assertIn(anchor, reaction_probe)
        for anchor in (
            "reactions list does not supply a stable reaction-resource url",
            "canonical positive numeric `id`",
            "do not accept a caller-supplied url",
            "reconstruct and compare the same url during the final re-read",
        ):
            self.assertIn(anchor, " ".join(probes.split()).lower())
        for anchor in (
            "'repos/<owner>/<repo>/issues/comments/<declaration_comment_id>'",
            "--method GET --include",
            "response's `Date` header",
            "`as_of_server_time`",
            "`as_of_api_url`",
            "fixed 2,592,000-second interval",
            "a caller-supplied declaration object",
        ):
            self.assertIn(anchor, probes)
        for anchor in (
            "reviewThreads",
            "isResolved",
            "hasNextPage",
            "endCursor",
            "REST-compatible `fullDatabaseId: BigInt`",
            "pullRequestReview { id fullDatabaseId }",
            "canonical positive decimal text",
            "REST `pull_request_review_id`",
            "orphan",
            "duplicate mapping",
            "parent-review conflict",
        ):
            self.assertIn(anchor, probes)
        self.assertNotIn("REST-compatible `databaseId`", probes)
        for anchor in (
            "An untrusted-identity or stale-scope artifact cannot win selection",
            "retain every terminal-looking instance as fail-closed evidence",
            "Never drop one and expose an older clean as the apparent winner",
            "an issue comment whose current body was edited uses `updated_at`",
        ):
            self.assertIn(anchor, probes)
        self.assertIn(
            "Do not use `gh pr view --repo` for this host-sensitive preflight",
            probes,
        )
        host_bound_metadata_probe = (
            "gh api --hostname <host> --method GET \\\n"
            "  repos/<owner>/<repo>/pulls/<number>"
        )
        self.assertGreaterEqual(probes.count(host_bound_metadata_probe), 2)
        self.assertNotIn("gh pr view <number> --repo <owner>/<repo>", probes)
        producer_policy_documents = {
            "skill": skill,
            "PR readiness": readiness,
            "GitHub probes": probes,
            "lane contracts": contracts,
            "prompt templates": templates,
            "repository policy": agents_policy,
            "skill interface": interface,
        }
        authority_consumer_documents = {
            "PR readiness": readiness,
            "GitHub probes": probes,
            "lane contracts": contracts,
            "prompt templates": templates,
            "skill interface": interface,
        }
        reaction_profile_entry_documents = {
            "skill": skill,
            "lane contracts": contracts,
            "prompt templates": templates,
            "egress consent": egress,
            "repository policy": agents_policy,
            "skill interface": interface,
        }
        if CI_PROFILE == "canonical":
            readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
            migration_journal = (
                REPO_ROOT
                / "docs/project_journal/2026/07/"
                / "2026-07-20-review-policy-migration-7f2001.md"
            ).read_text(encoding="utf-8")
            producer_policy_documents.update(
                {
                    "README": readme,
                    "migration journal": migration_journal,
                }
            )
            reaction_profile_entry_documents["README"] = readme
        for name, content in reaction_profile_entry_documents.items():
            normalized = " ".join(content.split()).lower().replace("`", "")
            with self.subTest(reaction_profile_entry_document=name):
                self.assertTrue("3–10" in normalized or "3-10" in normalized)
                self.assertTrue(
                    "never count" in normalized or "never counts" in normalized
                )
                self.assertTrue(
                    "canonical github rest issue comment" in normalized
                    or "canonical github rest issue-comment" in normalized
                )
                self.assertIn(
                    "if codex has suggestions, it will comment; otherwise it will "
                    "react with 👍.",
                    normalized,
                )
                for status in (
                    "compliant",
                    "warning",
                    "unknown",
                    "not-applicable",
                ):
                    self.assertIn(status, normalized)
                self.assertIn("eligible wait", normalized)
                self.assertIn("accepted", normalized)
                self.assertIn("selected", normalized)
                self.assertIn("basis", normalized)
        for name, content in producer_policy_documents.items():
            normalized = content.lower()
            with self.subTest(producer_policy_document=name):
                self.assertTrue(
                    "at most one" in normalized
                    or "one-request producer rule" in normalized
                    or "permits one exact" in normalized,
                    f"{name} must preserve the one-request producer rule",
                )
                self.assertTrue(
                    "never post a second" in normalized
                    or "never permits a second" in normalized
                    or "never a second or third" in normalized,
                    f"{name} must forbid another same-scope request",
                )
                self.assertIn("base-changed-same-head", normalized)
                self.assertIn("empty or anchor commit", normalized)

        for name, content in authority_consumer_documents.items():
            with self.subTest(authority_consumer=name):
                self.assertIn("github-codex-evidence-authority.md", content)
                normalized = content.lower().replace("`", "")
                self.assertNotIn(
                    "predeclared provider_profile",
                    normalized,
                )
                self.assertNotIn(
                    "selected provider_profile was predeclared",
                    normalized,
                )
                for field in (
                    "request_policy",
                    "provider_profile",
                    "evidence_basis",
                ):
                    self.assertIn(field, content)
                self.assertIn(
                    "pending while bounded waiting is meaningful",
                    content.lower(),
                )
        self.assertNotIn(
            "predeclared provider_profile",
            skill.lower().replace("`", ""),
        )

        for content in (readiness, probes, contracts, authority):
            normalized = " ".join(content.split()).lower().replace("`", "")
            self.assertIn("duplicate-observed", normalized)
            self.assertTrue(
                "final re-read" in normalized
                or "final reread" in normalized
                or (
                    "immediately before success" in normalized
                    and "re-read" in normalized
                )
            )
        self.assertIn("never post a second", templates.lower())
        self.assertIn(
            "does not require request/run attribution",
            authority.lower(),
        )
        self.assertIn(
            "This blocker does not reject a complete `thumbs-up-clean` result",
            skill,
        )
        for content in (skill, interface, templates):
            normalized = content.lower().replace("`", "")
            self.assertIn("provider_profile: null", normalized)
            self.assertIn("evidence_basis: null", normalized)
        self.assertIn(
            "fixed authority baseline has no accepted no-start body grammar",
            skill.lower(),
        )
        normalized_authority = " ".join(authority.split()).lower()
        for anchor in (
            "accepted structured capability/installation schema set is empty",
            "no current metadata document may prove",
            "authoritative api/issuer",
            "schema identifier and version",
            "repository/installation binding",
            "integration/service state is unknown rather than unavailable",
        ):
            self.assertIn(anchor, normalized_authority)
        for content in (
            readiness,
            probes,
            contracts,
            delivery,
            interface,
            templates,
        ):
            normalized = " ".join(content.split()).lower()
            self.assertTrue(
                "empty accepted structured capability/installation schema set"
                in normalized
                or "accepted structured capability/installation schema set 为空"
                in normalized
            )
            self.assertNotIn(
                "directly known or proved by authenticated structured "
                "capability or installation metadata",
                normalized,
            )
        for content in (readiness, probes, contracts):
            normalized = content.lower()
            self.assertIn(
                "fixed authority baseline has no accepted no-start body grammar",
                normalized,
            )
            self.assertNotIn(
                "proved by an authenticated exact-provider response",
                normalized,
            )
        self.assertIn(
            "A changed `baseRefOid` does not create another outcome when "
            "`pr_merge_base` and head are unchanged",
            probes,
        )
        for content in (probes, contracts, interface, templates, delivery):
            normalized = content.lower().replace("`", "")
            self.assertIn("nonterminal/check-only", normalized)
            self.assertIn("pending while bounded waiting is meaningful", normalized)
            self.assertIn("malformed", normalized)
            self.assertIn("ambiguous", normalized)
            self.assertTrue("immediate" in normalized or "立即" in normalized)
        for content in (
            skill,
            readiness,
            probes,
            contracts,
            templates,
            interface,
            delivery,
            egress,
            agents_policy,
        ):
            normalized = " ".join(content.split()).lower()
            self.assertTrue(
                "fixed terminal-payload grammar" in normalized
                or "fixed clean/finding/inline-parent grammar" in normalized
                or "fixed terminal grammar" in normalized
            )
            self.assertIn("terminal-looking", normalized)
            self.assertIn("malformed", normalized)
        for content in (
            skill,
            readiness,
            probes,
            contracts,
            templates,
            interface,
            delivery,
            agents_policy,
        ):
            normalized = " ".join(content.split()).lower().replace("`", "")
            self.assertTrue(
                "historical/current" in normalized
                or "historical and current" in normalized
                or "every sampled outcome" in normalized
                or ("historical" in normalized and "current outcome" in normalized)
            )
            self.assertIn("parent", normalized)
            self.assertIn("child", normalized)
            self.assertIn("+1", normalized)
            self.assertIn("declaration", normalized)
            self.assertIn("digest", normalized)
            self.assertTrue(
                "strict ordering" in normalized
                or "strict server ordering" in normalized
                or "严格顺序" in normalized
                or (
                    "strict reaction.created_at"
                    " > request.request_server_time" in normalized
                )
            )
            self.assertIn("same-scope request", normalized)
            self.assertTrue(
                "cross-parent" in normalized
                or "later duplicate request" in normalized
                or "later request" in normalized
            )
        self.assertNotIn("expected Codex integration identity", probes)

        for anchor in (
            "Resolve the local frozen range and PR selector independently",
            "base_sha == pr_merge_base and head_sha == pr_head_oid",
            "same-head/different-base range is blocked-input scope-mismatch",
        ):
            self.assertIn(anchor, interface)

    def test_base_only_retarget_precedes_scope_mismatch_and_preserves_authority(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        priority_anchor = (
            "before applying the generic same-head/different-base "
            "`scope-mismatch` branch"
        )
        authority_documents = (skill, readiness, probes, contracts, templates)
        for content in authority_documents:
            with self.subTest(authority_document=content[:40]):
                normalized = content.lower()
                self.assertIn(priority_anchor, normalized)
                self.assertIn("caller-supplied", content)
                self.assertIn("pr-derived", content)
                self.assertIn("range_origin", content)
                self.assertIn("base-only-retarget-state-machine.json", content)
                self.assertIn("base-changed-same-head", content)

        workflow = skill.split("## Workflow", 1)[1].lower()
        self.assertLess(
            workflow.index(priority_anchor),
            workflow.index("otherwise a selected pr's explicit frozen range satisfies"),
        )

        selected_pr_preflight = readiness.split("After a PR is selected", 1)[1]
        selected_pr_preflight = selected_pr_preflight.split(
            "Reserve `blocked-authorization`", 1
        )[0].lower()
        self.assertLess(
            selected_pr_preflight.index("base-only-retarget-state-machine.json"),
            selected_pr_preflight.index("otherwise require exact equality"),
        )

        gate_sequence = readiness.split("## Gate Sequence", 1)[1].lower()
        self.assertLess(
            gate_sequence.index(priority_anchor),
            gate_sequence.index("otherwise, when no explicit range exists"),
        )

        probe_classification = probes.split("Classify precisely", 1)[1].lower()
        self.assertLess(
            probe_classification.index("post-request base-only retarget"),
            probe_classification.index("any other selected pr"),
        )
        self.assertIn(
            "stops before local lanes",
            selected_pr_preflight,
        )
        self.assertIn(
            "a recovery pass proceeds to the local lanes",
            selected_pr_preflight,
        )

    def test_base_only_retarget_state_machine_allows_only_authorized_recovery(
        self,
    ) -> None:
        machine_path = SKILL_ROOT / "references/base-only-retarget-state-machine.json"
        machine = json.loads(machine_path.read_text(encoding="utf-8"))

        self.assertEqual(machine["version"], 1)
        self.assertEqual(
            machine["event"],
            "request-time-merge-base-changed-with-same-head",
        )
        self.assertEqual(
            machine["range_origin"],
            {
                "record_location": "parent-owned-audit",
                "required_fields": ["kind", "base_sha", "head_sha"],
                "allowed_kinds": ["caller-supplied", "pr-derived"],
                "original_caller_endpoints_are_immutable": True,
            },
        )
        self.assertEqual(
            machine["github_lane"],
            {
                "action": "never-post-replacement-same-head",
                "status": "triple-inconclusive",
            },
        )

        transitions = {entry["name"]: entry for entry in machine["transitions"]}
        self.assertEqual(
            set(transitions),
            {
                "missing-range-origin",
                "stale-caller-range",
                "forbidden-parent-rewrite-of-caller-range",
                "caller-supplied-current-recovery",
                "stale-pr-derived-range",
                "pr-derived-current-recovery",
            },
        )
        expected_actions = {
            "missing-range-origin": (
                "unknown",
                "any",
                "any",
                "stop-before-local-lanes",
                "range-origin-unverified",
            ),
            "stale-caller-range": (
                "caller-supplied",
                "inherited-stale",
                False,
                "stop-before-local-lanes",
                "base-changed-same-head",
            ),
            "forbidden-parent-rewrite-of-caller-range": (
                "caller-supplied",
                "parent-rederived-current",
                True,
                "stop-before-local-lanes",
                "caller-authority-required",
            ),
            "caller-supplied-current-recovery": (
                "caller-supplied",
                "caller-supplied-current",
                True,
                "run-local-lanes",
                "local-recovery-authorized",
            ),
            "stale-pr-derived-range": (
                "pr-derived",
                "inherited-stale",
                False,
                "stop-before-local-lanes",
                "base-changed-same-head",
            ),
            "pr-derived-current-recovery": (
                "pr-derived",
                "normally-rederived-current",
                True,
                "run-local-lanes",
                "local-recovery-authorized",
            ),
        }
        for name, expected in expected_actions.items():
            transition = transitions[name]
            actual = (
                transition["invalidated_origin"],
                transition["recovery_source"],
                transition["current_range_equals_current_pr"],
                transition["local_action"],
                transition["reason"],
            )
            with self.subTest(transition=name):
                self.assertEqual(actual, expected)

        for path in (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/pr-readiness.md",
            SKILL_ROOT / "references/review-lane-contracts.md",
            SKILL_ROOT / "references/github-pr-probes.md",
            SKILL_ROOT / "references/review-prompt-templates.md",
        ):
            content = path.read_text(encoding="utf-8")
            with self.subTest(state_machine_reference=str(path)):
                self.assertIn("base-only-retarget-state-machine.json", content)
                self.assertIn("range_origin", content)
                self.assertIn("caller-supplied", content)
                self.assertIn("pr-derived", content)
                self.assertIn("run", content.lower())
                self.assertIn("local lane", content.lower())

    def test_named_single_prompt_uses_clear_context_codex_without_a_full_diff(
        self,
    ) -> None:
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        single = templates[
            templates.index(
                "## Named Single: Fresh-Context Codex Reviewer"
            ) : templates.index("## Named Double: Actual Claude Code Lane")
        ]

        for anchor in (
            "Workspace: {clean_worktree}",
            "Base SHA: {base_sha}",
            "Head SHA: {head_sha}",
            "Frozen review range: {base_sha}..{head_sha}",
            "Trusted control-plane bundle absolute source: {trusted_bundle_absolute_path}",
            "Trusted control-plane bundle version: {trusted_bundle_version}",
            "Trusted control-plane bundle SHA-256: {trusted_bundle_sha256}",
            "Sanitized Git argv prefix (exact token sequence): {sanitized_git_argv_prefix}",
            "Authoritative review skill path: {review_skill_path}",
            "Authoritative review skill version/digest: {review_skill_version_or_digest}",
            "clean, independent, read-only Git worktree",
            "does not include a prebuilt full diff",
            "obtain range metadata, changed paths, hunks",
            "verify that the exact authoritative review skill path above exists",
            "missing or mismatched",
            "never choose another installed copy",
            "Load exactly that review skill",
            "load the trusted review skill",
            "domain skill",
            "AGENTS.md",
            "project-guidance document",
            "Do not run bare `git`",
            "--no-ext-diff --no-textconv",
            '`fork_turns="none"`',
        ):
            self.assertIn(anchor, single)
        self.assertNotIn("{diff_file}", single)
        self.assertNotIn("Primary diff:", single)

    def test_named_double_and_triple_prompts_require_the_actual_provider_lanes(
        self,
    ) -> None:
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        double = templates[
            templates.index(
                "## Named Double: Actual Claude Code Lane"
            ) : templates.index("## Named Triple: GitHub Cloud Codex Trigger")
        ]
        triple = templates[
            templates.index(
                "## Named Triple: GitHub Cloud Codex Trigger"
            ) : templates.index("## Low-Level Helper Results")
        ]

        for anchor in (
            "actual Anthropic Claude Code",
            "independent from the Codex reviewer worktree and read-only",
            "Workspace: {claude_readonly_workspace}",
            "Frozen review range: {base_sha}..{head_sha}",
            "Canonical Claude lane contract version: {review_contract_version}",
            "Explicitly read repository-wide AGENTS.md",
            "domain skills",
            "no prepared diff or other reviewer's output is supplied",
            "supplemental Copilot diagnostic",
            "does not complete named double",
        ):
            self.assertIn(anchor, double)

        def assert_shared_discovery_order(prompt: str) -> None:
            anchors = (
                "repository-wide AGENTS.md",
                "changed-path metadata",
                "path-scoped AGENTS.md",
                "domain skill",
                "before inspecting hunks",
            )
            positions = [prompt.index(anchor) for anchor in anchors]
            self.assertEqual(positions, sorted(positions))
            project_guidance_position = min(
                position
                for phrase in ("project-guidance", "project guidance")
                if (position := prompt.find(phrase)) >= 0
            )
            self.assertGreater(project_guidance_position, positions[3])
            self.assertLess(project_guidance_position, positions[4])

        assert_shared_discovery_order(
            templates[
                templates.index(
                    "## Named Single: Fresh-Context Codex Reviewer"
                ) : templates.index("## Named Double: Actual Claude Code Lane")
            ]
        )
        assert_shared_discovery_order(double)
        for anchor in (
            "@codex review",
            "exact-host `github.com` PR",
            "sqbu-github.cisco.com",
            "identity in `{hoteng, hoteng_cisco}`",
            "`requested: triple`, `effective: double`",
            "Posting the comment requests the third lane but does not complete it",
            "complete terminal provider-authored current-head findings payload",
            "service-start evidence only",
            "never completes triple or proves clean/no-findings",
            "effective: triple-inconclusive",
            "GitHub lane status `blocked-authorization`",
        ):
            self.assertIn(anchor, triple)
        self.assertNotIn("equivalent", triple)

    def test_canonical_claude_lane_has_a_direct_nonhelper_launch_contract(
        self,
    ) -> None:
        contract = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "Do not route this lane through `isolated_review`",
            "Start a new actual `claude` process",
            "working directory set to that worktree",
            "Send the small control prompt through stdin",
            "--no-session-persistence",
            "--strict-mcp-config",
            "--tools Read,Grep,Glob,Bash",
            "--disallowedTools Edit,Write,NotebookEdit,WebFetch,WebSearch,Task",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
            "disableBundledSkills: true",
            '"disableBundledSkills": true',
            "`--safe-mode` alone is not evidence that bundled skills are absent",
            '"denyWrite": ["/"]',
            "owner-private lane-local repository",
            "private destination inventory is exact",
            "remote transport",
            "GIT_NO_LAZY_FETCH=1",
            "locally complete",
            "never run `fetch`, `pull`",
            "global write denial",
            "critical sensitive roots",
            "not a global host-read whitelist",
            "Claude Code `2.1.212` is the audited per-version stream-schema baseline, not a global eligibility pin.",
            "cannot attest the final merged sandbox",
            "actual Claude process",
        ):
            self.assertIn(anchor, contract)
        self.assertNotIn("Primary diff:", contract)

    def test_named_claude_compatible_version_preflight_is_fail_closed(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        helper_path = SCRIPTS / "named_claude_preflight"
        helper = helper_path.read_text(encoding="utf-8")
        module = (SCRIPTS / "review_runtime/named_claude_preflight.py").read_text(
            encoding="utf-8"
        )
        provenance = (SCRIPTS / "review_runtime/claude_provenance.py").read_text(
            encoding="utf-8"
        )
        capabilities = (SCRIPTS / "review_runtime/claude_capabilities.py").read_text(
            encoding="utf-8"
        )
        policy_path = SCRIPTS / "review_runtime/claude_version_policy.py"
        policy = policy_path.read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            for anchor in (
                "named_claude_preflight",
                "`>=2.1.211,<3.0.0`",
                "claude_version_policy.py",
                "<resolved-compatible-claude-path>",
            ):
                self.assertIn(anchor, content)
            self.assertIn("mandatory", content)
            self.assertIn("`--help`", content)
            self.assertIn("advertised capability surface", content)
            self.assertIn("final merged sandbox", content)
            normalized = content.lower()
            self.assertIn("separate", normalized)
            self.assertIn("explicit", normalized)
            self.assertIn("official installer", normalized)
            self.assertIn("authorization", normalized)
            self.assertIn("install", normalized)
            self.assertIn("double", content)
            self.assertIn("blocked", content)
            self.assertIn("triple", content)
        for content in (skill, canonical):
            self.assertIn("compatible-version-selected", content)
            self.assertIn("claude-stream-compatibility.json", content)
        for content in (contracts, canonical):
            for anchor in (
                "highest compatible",
                "side-by-side",
                "descriptor-bound source identity",
                "private digest-verified",
                "snapshot",
                "--preflight-result",
            ):
                self.assertIn(anchor, content)
        for anchor in (
            "explicit absolute `--claude-path` override",
            "`--claude-version`",
            "An explicit override is authoritative",
            "Candidate presence is tri-state",
            "highest compatible stable side-by-side install",
            "candidate-inspection-inconclusive",
            "compatible-version-unavailable",
            "unsupported-version",
            "signed-version-identity-mismatch",
            "publisher-verification-failed",
            "fixed credential-free environment",
            "never downloads",
            "active symlink",
            "empty stdin",
            "fixed `/` cwd",
            "no prompt, credential, repository, range, PR, or workspace input",
            "one bounded JSON object",
            "fixed resolved source path",
            "a requested double remains double-but-blocked",
            "effective double is still incomplete until Claude succeeds",
            "Caller `PATH` is ignored",
            "before any probe",
            "private digest-verified executable snapshot",
            "resolve the system temporary parent to its canonical path",
            "macOS `/tmp -> /private/tmp`",
            "a fresh descriptor-bound hash of the mutable source against the signed size and SHA-256",
            "stat identity alone is insufficient",
            "Never collapse uncertainty into deterministic unavailability",
        ):
            self.assertIn(anchor, canonical)
        self.assertTrue(helper_path.is_file())
        self.assertTrue(helper.startswith("#!/usr/bin/env python3\n"))
        for anchor in (
            "from .claude_version_policy import (",
            "CLAUDE_COMPATIBILITY_SPEC",
            '"explicit-override"',
            '"side-by-side-compatible"',
            '"active-installed"',
            '"HOME": "/nonexistent"',
            'CAPABILITY_PROBE_CWD = pathlib.Path("/")',
            "stdin=None",
            '"classification": classification',
            '"compatible-version-unavailable"',
            '"unsupported-version"',
            '"signed-version-identity-mismatch"',
            '"publisher-verification-failed"',
            "verify_claude_release(",
            "version=release_version",
            "parse_compatible_release_version(declared_version)",
            "materialize_verified_executable(",
            "def _verified_source_matches_signed_artifact(",
            "version_probe(snapshot.executable)",
            "help_probe(snapshot.executable)",
            "_validate_help_probe(verified.help_probe_result)",
            "load_stream_contract()",
            '"compatible-version-selected"',
            '"ctime_ns"',
            '"executable-identity-drift"',
            '"/opt/homebrew/bin/claude"',
            '"/usr/local/bin/claude"',
        ):
            self.assertIn(anchor, module)
        self.assertIn("source_identity", provenance)
        self.assertIn("_stat_identity(opened_before)", provenance)
        self.assertIn("_require_verified_source_identity", provenance)
        self.assertNotIn("version_probe(resolved)", module)
        self.assertNotIn("help_probe(resolved)", module)
        self.assertNotIn("shutil.which", module)
        self.assertLess(
            module.index("verified = verifier("),
            module.index("completed = verified.version_probe_result"),
        )
        self.assertLess(
            module.index("version_completed = version_probe(snapshot.executable)"),
            module.index("help_completed = help_probe(snapshot.executable)"),
        )
        self.assertLess(
            module.index(
                "if after_resolved != resolved or not _verified_source_matches_signed_artifact("
            ),
            module.index("verified.artifact.version != declared_version"),
        )
        self.assertEqual(
            policy.count('CLAUDE_COMPATIBILITY_SPEC = ">=2.1.211,<3.0.0"'),
            1,
        )
        for consumer in (module, provenance, capabilities):
            self.assertIn("claude_version_policy", consumer)
            self.assertNotIn('">=2.1.211,<3.0.0"', consumer)

    def test_claude_compatibility_policy_is_floating_stable_and_not_exact_pinned(
        self,
    ) -> None:
        self.assertEqual(
            claude_version_policy.CLAUDE_COMPATIBILITY_SPEC,
            ">=2.1.211,<3.0.0",
        )
        self.assertEqual(
            claude_version_policy.CLAUDE_MINIMUM_VERSION,
            (2, 1, 211),
        )
        self.assertEqual(
            claude_version_policy.CLAUDE_MAXIMUM_VERSION,
            (3, 0, 0),
        )
        policy_path = SCRIPTS / "review_runtime/claude_version_policy.py"
        self.assertTrue(policy_path.is_file())
        self.assertTrue(
            (SCRIPTS / "review_runtime/claude_stream_contract.py").is_file()
        )
        self.assertTrue(claude_stream_contract.COMPATIBILITY_PATH.is_file())
        self.assertTrue(claude_stream_contract.BASELINE_PATH.is_file())
        self.assertTrue(claude_stream_contract.PROFILE_PATH.is_file())
        production_python = sorted((SCRIPTS / "review_runtime").glob("*.py"))
        production_python.append(SCRIPTS / "validate_claude_stream.py")
        range_literal_sources = {
            path.relative_to(SCRIPTS).as_posix(): path.read_text(
                encoding="utf-8"
            ).count(">=2.1.211,<3.0.0")
            for path in production_python
            if ">=2.1.211,<3.0.0" in path.read_text(encoding="utf-8")
        }
        self.assertEqual(
            range_literal_sources,
            {policy_path.relative_to(SCRIPTS).as_posix(): 1},
        )
        accepted = {
            "2.1.211": (2, 1, 211),
            "2.1.212": (2, 1, 212),
            "2.1.216": (2, 1, 216),
            "2.1.999": (2, 1, 999),
            "2.99.0": (2, 99, 0),
        }
        for version, parsed in accepted.items():
            with self.subTest(version=version):
                self.assertEqual(
                    claude_version_policy.parse_compatible_release_version(version),
                    parsed,
                )
                self.assertTrue(
                    claude_version_policy.is_compatible_release_version(version)
                )
        for version in (
            "2.1.210",
            "2.1.211-alpha.1",
            "2.1.216+local",
            "3.0.0",
            "3.0.1",
        ):
            with self.subTest(version=version):
                with self.assertRaises(claude_version_policy.ClaudeVersionPolicyError):
                    claude_version_policy.parse_compatible_release_version(version)
                self.assertFalse(
                    claude_version_policy.is_compatible_release_version(version)
                )

        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        preflight = (SCRIPTS / "review_runtime/named_claude_preflight.py").read_text(
            encoding="utf-8"
        )
        baseline_sentence = (
            "Claude Code `2.1.212` is the audited per-version stream-schema "
            "baseline, not a global eligibility pin."
        )
        for content in (skill, canonical):
            self.assertIn("The canonical Claude Code compatibility range is", content)
            self.assertIn("`>=2.1.211,<3.0.0`", content)
            self.assertIn("defined once in", content)
            self.assertIn("claude_version_policy.py", content)
            self.assertIn(baseline_sentence, content)
            self.assertNotIn("exact-version-mismatch", content)
            self.assertNotIn("exact-version-unavailable", content)
            self.assertNotIn(
                "requires the publisher-verified Claude Code CLI version to be exactly",
                content,
            )
            self.assertNotIn("require exactly Claude Code `2.1.212`", content)
        for forbidden in (
            "REQUIRED_CLAUDE_VERSION",
            "exact-version-mismatch",
            "exact-version-unavailable",
            '"2.1.212"',
        ):
            self.assertNotIn(forbidden, preflight)

        binding, compatibility_raw, profile_raw = (
            claude_stream_contract.load_stream_contract()
        )
        self.assertEqual(
            binding.schema_id,
            claude_stream_contract.COMPATIBILITY_SCHEMA_ID,
        )
        self.assertEqual(len(binding.digest), 64)
        self.assertEqual(len(binding.compatibility_digest), 64)
        self.assertEqual(len(binding.baseline_digest), 64)
        self.assertEqual(len(binding.capability_digest), 64)
        compatibility = json.loads(compatibility_raw)
        profile = json.loads(profile_raw)
        baseline = json.loads(
            claude_stream_contract.BASELINE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(compatibility["baseline_version"], "2.1.212")
        self.assertEqual(baseline["claude_code_version"], "2.1.212")
        self.assertEqual(
            baseline["init_event"]["field_contracts"]["apiKeySource"],
            {
                "rule": "exact_runtime_binding",
                "binding_field": "api_key_source",
                "accepted_values": ["ANTHROPIC_API_KEY", "none"],
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        self.assertEqual(
            compatibility["version_policy"],
            "review_runtime.claude_version_policy.CLAUDE_COMPATIBILITY_SPEC",
        )
        self.assertEqual(
            compatibility["compatibility_mode"],
            "strict-version-and-launch-profiles",
        )
        self.assertEqual(compatibility["profile_schema"], "claude-stream-schema.json")
        self.assertEqual(
            compatibility["profile_version_policy"],
            claude_version_policy.CLAUDE_COMPATIBILITY_SPEC,
        )
        self.assertEqual(
            compatibility["version_profiles"],
            {
                "legacy-base": ">=2.1.211,<2.1.216",
                "extended-2x": ">=2.1.216,<3.0.0",
            },
        )
        self.assertEqual(
            set(compatibility["launch_profiles"]),
            {"helper-darwin", "helper-linux", "named-direct"},
        )
        self.assertEqual(
            profile["claude_code_version"],
            {
                "rule": "strict_release_semver_range",
                "minimum_inclusive": "2.1.211",
                "maximum_exclusive": "3.0.0",
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            incompatible_path = pathlib.Path(temp_dir) / "compatibility.json"
            incompatible_profile = dict(compatibility)
            incompatible_profile["unknown_future_surface"] = True
            incompatible_path.write_text(
                json.dumps(incompatible_profile),
                encoding="utf-8",
            )
            with self.assertRaises(claude_stream_contract.ClaudeStreamContractError):
                claude_stream_contract.load_stream_contract(
                    compatibility_path=incompatible_path,
                    baseline_path=claude_stream_contract.BASELINE_PATH,
                )

    def test_canonical_claude_stream_evidence_is_unique_bound_and_fail_closed(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )
        validator_path = SCRIPTS / "validate_claude_stream.py"
        validator = validator_path.read_text(encoding="utf-8")
        stream_schema = json.loads(
            (SKILL_ROOT / "references/claude-stream-schema.json").read_text(
                encoding="utf-8"
            )
        )
        compatibility_profile = json.loads(
            (SKILL_ROOT / "references/claude-stream-compatibility.json").read_text(
                encoding="utf-8"
            )
        )

        for anchor in (
            "## Structured Init And Terminal Evidence",
            "first nonblank record",
            "sole event with `type: system` and `subtype: init`",
            "last nonblank record",
            "sole event with `type: result`",
            "`subtype` is the string `success`",
            "`is_error` is the boolean `false`",
            "`cwd` equals the resolved lane-unique clean worktree exactly",
            "`permissionMode` equals `dontAsk`",
            "duplicate-free set exactly equal to `Read`, `Grep`, `Glob`, and `Bash`",
            "`mcp_servers`, `slash_commands`, `skills`, and `plugins`",
            "`claude_code_version` equals the publisher-verified preflight version",
            "`apiKeySource` is exactly the string `none`",
            "validator/schema compatibility surface can represent `ANTHROPIC_API_KEY`",
            "current `run-claude` launcher exposes no API-key input",
            "`ANTHROPIC_API_KEY` therefore cannot satisfy this canonical lane",
            "`result` is a required string whose `strip()` value is nonempty",
            "`modelUsage` is a required nonempty object",
            "every key is a nonempty model-ID string",
            "every value is an object",
            "`error` and `errors`, when present, are explicitly empty",
            "`api_error_status`, when present, is `null` or a whitespace-only string",
            "`permission_denials`, when present, is an empty array",
            "nonempty/malformed `permission_denials` fails closed",
            "The canonical Claude Code compatibility range is",
            "`>=2.1.211,<3.0.0`",
            "defined once in",
            "claude_version_policy.py",
            "Claude Code `2.1.212` is the audited per-version stream-schema baseline, not a global eligibility pin.",
            "adapts the baseline `claude_code_version` constant to the exact accepted preflight-selected version",
            "exact-version additive metadata contracts",
            "selects a reviewed closed profile by the exact preflight version",
            "`legacy-base` for `>=2.1.211,<2.1.216`",
            "`extended-2x` for `>=2.1.216,<3.0.0`",
            "does not prove the final merged native sandbox",
            "merged admin-managed permission arrays",
            "path-rule evaluation",
            "floating-point tokens are parsed",
            "negative underflow",
            "`-h`, `--help`",
            "Exit status zero is reserved for `accepted` output",
            "A bare child exit code 401",
            "non-authentication refresh failure",
            "Generic token counting, usage, budget, quota, capacity, rate-limit, or limit failures are not authentication evidence",
            "credential-file or other ambiguous credential I/O",
            "terminal.model-entitlement-denial",
            "terminal.organization-policy-denial",
        ):
            self.assertIn(anchor, canonical)
        for content in (skill, contracts, runtime):
            self.assertIn("exactly one leading `system/init`", content)
            self.assertIn("one trailing terminal `result`", content)
            self.assertIn("fail closed", content.lower())
        for content in (skill, contracts):
            self.assertIn("--process-returncode <child-returncode>", content)
            self.assertIn("--preflight-result", content)
            self.assertIn(
                "outside the model-visible worktree", " ".join(content.split())
            )
        for content in (contracts,):
            self.assertIn("optional nonempty `session_id`", content)
            self.assertIn("unknown init field", content)
            self.assertIn("missing, invalid, or nonzero child return code", content)
            self.assertIn("structured `blocked` or `blocked-authentication`", content)
            self.assertIn("bare exit code", content)
        for content in (skill, contracts, canonical):
            self.assertIn("validate_claude_stream.py", content)
            self.assertIn("classification: accepted", content)
        self.assertIn("outside the reviewer-visible workspace", skill)
        for content in (contracts, canonical):
            self.assertIn(
                "outside the model-visible worktree",
                " ".join(content.split()),
            )
        for content in (skill, canonical):
            self.assertIn("claude-stream-compatibility.json", content)
        self.assertTrue(validator_path.is_file())
        self.assertTrue(validator.startswith("#!/usr/bin/env python3\n"))
        for anchor in (
            "MAX_SCHEMA_BYTES",
            "max_bytes: int = 8 * 1024 * 1024",
            "object_pairs_hook=_reject_duplicate_keys",
            "parse_constant=_reject_nonstandard_constant",
            "parse_float=_bounded_parse_float",
            "MAX_JSON_FLOAT_CHARACTERS",
            "MAX_JSON_FLOAT_SIGNIFICAND_DIGITS",
            "MAX_JSON_FLOAT_EXPLICIT_EXPONENT_MAGNITUDE",
            '"accepted": 0',
            '"blocked": 1',
            '"blocked-authentication": 2',
            '"inconclusive": 3',
            '"--process-returncode"',
            '"--preflight-result"',
            "_read_preflight_evidence",
            "_validate_preflight_evidence",
            "claude_stream_contract.load_stream_contract",
            '"validator.preflight-evidence-invalid"',
            '"process.returncode.invalid"',
            '"process.returncode.nonzero"',
            '"init.unknown-field"',
            "INIT_OPTIONAL_FIELDS",
            "CLAUDE_CODE_VERSION_CONTRACT",
            "AUTHENTICATION_SOURCE_TO_API_KEY_SOURCE",
            "INIT_PROFILE_CONTRACT",
            "EXTENDED_INIT_REQUIRED_FIELDS",
            "runtime_binding_from_preflight_result",
            '"--authentication-source"',
        ):
            self.assertIn(anchor, validator)
        self.assertEqual(
            stream_schema["claude_code_version"],
            {
                "rule": "strict_release_semver_range",
                "minimum_inclusive": "2.1.211",
                "maximum_exclusive": "3.0.0",
            },
        )
        init_contract = stream_schema["init_event"]
        self.assertEqual(
            stream_schema["process_returncode"],
            {
                "rule": "exact_int",
                "missing_or_invalid": {
                    "classification": "inconclusive",
                    "reason": "process.returncode.invalid",
                },
                "accepted_requires": 0,
                "nonzero_precedence": {
                    "accepted": {
                        "classification": "inconclusive",
                        "reason": "process.returncode.nonzero",
                    },
                    "blocked": "preserve",
                    "blocked-authentication": "preserve",
                    "inconclusive": {
                        "classification": "inconclusive",
                        "append_reason": "process.returncode.nonzero",
                    },
                },
            },
        )
        self.assertFalse(init_contract["additional_fields"])
        self.assertEqual(init_contract["optional_fields"], ["session_id"])
        self.assertEqual(
            init_contract["optional_field_contracts"]["session_id"],
            {"rule": "nonempty_string", "failure": "inconclusive"},
        )
        self.assertEqual(
            compatibility_profile,
            {
                "schema_id": "claude-code-stream-compatible-v1",
                "version_policy": (
                    "review_runtime.claude_version_policy.CLAUDE_COMPATIBILITY_SPEC"
                ),
                "compatibility_mode": "strict-version-and-launch-profiles",
                "baseline_schema": "claude-2.1.212-stream-schema.json",
                "baseline_version": "2.1.212",
                "profile_schema": "claude-stream-schema.json",
                "profile_version_policy": ">=2.1.211,<3.0.0",
                "version_profiles": {
                    "legacy-base": ">=2.1.211,<2.1.216",
                    "extended-2x": ">=2.1.216,<3.0.0",
                },
                "version_adaptations": (claude_stream_contract.VERSION_ADAPTATIONS),
                "launch_profiles": [
                    "helper-darwin",
                    "helper-linux",
                    "named-direct",
                ],
                "fail_closed_surfaces": [
                    "stream_envelope",
                    "init_field_set",
                    "init_field_values",
                    "intermediate_event_field_sets",
                    "intermediate_session_binding",
                    "terminal_field_set",
                    "terminal_variants",
                    "model_identity",
                ],
            },
        )
        self.assertNotIn("when the runtime reports it", canonical)

    def test_canonical_claude_structured_errors_have_one_failure_classifier(
        self,
    ) -> None:
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        envelope_anchor = "A missing, duplicate, malformed, out-of-order, or trailing contract event makes the lane `inconclusive`"
        classifier_anchor = "A structurally valid terminal event that fails the success acceptance schema is passed to the failure classifier below"
        permission_anchor = "Classify a structurally valid permission denial, output truncation/abnormal stop, exact-model mismatch, or configuration/policy mismatch as `blocked`"
        authentication_anchor = "Classify only a structurally valid recognized `Login expired`, explicit HTTP/status 401, explicit OAuth/credential/login/authentication/token refresh error, or directly adjacent expired/invalid/unauthorized authentication state as `blocked-authentication`"
        token_non_authentication_anchor = "Generic token counting, usage, budget, quota, capacity, rate-limit, or limit errors"
        init_blocker_anchor = "When a non-success terminal follows any deterministic init or terminal blocker, absence of error prose preserves `blocked`"
        fallback_anchor = "The validator emits `classification: blocked` with machine reason `terminal.model-entitlement-denial` or `terminal.organization-policy-denial`"
        for anchor in (
            envelope_anchor,
            classifier_anchor,
            permission_anchor,
            authentication_anchor,
            token_non_authentication_anchor,
            init_blocker_anchor,
            fallback_anchor,
        ):
            self.assertIn(anchor, canonical)
        self.assertNotIn("out-of-order, error-bearing, or trailing", canonical)
        self.assertLess(
            canonical.index(envelope_anchor), canonical.index(classifier_anchor)
        )
        self.assertLess(
            canonical.index(classifier_anchor), canonical.index(permission_anchor)
        )
        self.assertLess(
            canonical.index(classifier_anchor), canonical.index(authentication_anchor)
        )

    def test_codex_authoritative_playbook_source_is_parent_selected_and_exact(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        policy_scope = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        reviewer = (policy_scope / "agents/reviewer.toml").read_text(encoding="utf-8")
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        change_delivery = (
            SKILL_ROOT.parent / "change-delivery-workflow/SKILL.md"
        ).read_text(encoding="utf-8")

        for content in (skill, contracts, reviewer, change_delivery):
            normalized = content.lower()
            self.assertRegex(
                normalized,
                r"normally(?: this is)? the active installed copy",
            )
            self.assertIn("missing or mismatched", normalized)
        for content in (skill, contracts, reviewer, agents_policy, change_delivery):
            normalized = content.lower()
            self.assertIn("candidate-head markdown", normalized)
            self.assertIn("review subject", normalized)
            self.assertIn("independently trusted", normalized)
        self.assertIn("pinned outside", contracts)
        self.assertNotIn(
            "must be the frozen repo-local copy at the review head",
            change_delivery,
        )
        self.assertIn(
            "exact parent-selected authoritative playbook path/version or digest",
            change_delivery,
        )
        for content in (skill, contracts, reviewer, change_delivery):
            self.assertNotIn("from its normal skill environment", content)
        for anchor in (
            "Authoritative review skill path: {review_skill_path}",
            "Authoritative review skill version/digest: {review_skill_version_or_digest}",
            "verify that the exact authoritative review skill path above exists",
            "report the lane blocked",
            "never choose another installed copy",
        ):
            self.assertIn(anchor, templates)
        self.assertNotIn("{review_skill_path_or_version}", templates)

    def test_floating_claude_schema_closes_versioned_init_and_terminal_fields(
        self,
    ) -> None:
        schema_path = SKILL_ROOT / "references/claude-stream-schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        self.assertEqual(
            schema["claude_code_version"],
            {
                "rule": "strict_release_semver_range",
                "minimum_inclusive": "2.1.211",
                "maximum_exclusive": "3.0.0",
            },
        )
        self.assertEqual(
            schema["stream_contract"]["first_nonblank_event"],
            {"type": "system", "subtype": "init"},
        )
        self.assertEqual(
            schema["stream_contract"]["last_nonblank_event"],
            {"type": "result"},
        )
        self.assertEqual(schema["stream_contract"]["init_event_count"], 1)
        self.assertEqual(schema["stream_contract"]["result_event_count"], 1)
        self.assertTrue(
            schema["stream_contract"]["matching_session_id_when_both_present"]
        )
        self.assertEqual(schema["stream_contract"]["max_bytes"], 8 * 1024 * 1024)
        self.assertEqual(
            schema["stream_contract"]["floating_number_representation"], "decimal"
        )
        self.assertEqual(schema["stream_contract"]["max_float_characters"], 256)
        self.assertEqual(schema["stream_contract"]["max_float_significand_digits"], 128)
        self.assertEqual(
            schema["stream_contract"]["max_float_explicit_exponent_magnitude"], 308
        )
        init_contract = schema["init_event"]
        self.assertFalse(init_contract["additional_fields"])
        self.assertEqual(init_contract["optional_fields"], ["session_id"])
        self.assertEqual(
            init_contract["optional_field_contracts"]["session_id"],
            {"rule": "nonempty_string", "failure": "inconclusive"},
        )
        profiles = init_contract["profiles"]
        self.assertEqual(profiles["selector"], "claude_code_version")
        self.assertEqual(
            set(profiles["variants"]),
            {"legacy-base", "extended-2x"},
        )
        legacy_profile = profiles["variants"]["legacy-base"]
        self.assertEqual(
            legacy_profile["version_range"],
            {
                "minimum_inclusive": "2.1.211",
                "maximum_exclusive": "2.1.216",
            },
        )
        self.assertEqual(legacy_profile["additional_required_fields"], [])
        self.assertEqual(legacy_profile["field_contracts"], {})
        extended_profile = profiles["variants"]["extended-2x"]
        self.assertEqual(
            extended_profile["version_range"],
            {
                "minimum_inclusive": "2.1.216",
                "maximum_exclusive": "3.0.0",
            },
        )
        extended_fields = {
            "agents",
            "analytics_disabled",
            "capabilities",
            "fast_mode_state",
            "output_style",
            "product_feedback_disabled",
            "uuid",
        }
        self.assertEqual(
            set(extended_profile["additional_required_fields"]),
            extended_fields,
        )
        self.assertEqual(
            set(extended_profile["field_contracts"]),
            extended_fields,
        )
        self.assertEqual(
            extended_profile["field_contracts"],
            {
                "output_style": {
                    "rule": "constant",
                    "value": "default",
                    "failure": "inconclusive",
                },
                "agents": {
                    "rule": "exact_ordered_array",
                    "values": ["claude", "Explore", "general-purpose", "Plan"],
                    "failure": "inconclusive",
                },
                "capabilities": {
                    "rule": "exact_ordered_array",
                    "values": ["interrupt_receipt_v1", "msg_lifecycle_v1"],
                    "failure": "inconclusive",
                },
                "analytics_disabled": {
                    "rule": "constant",
                    "value": True,
                    "failure": "inconclusive",
                },
                "product_feedback_disabled": {
                    "rule": "boolean",
                    "failure": "inconclusive",
                },
                "uuid": {
                    "rule": "nonempty_string",
                    "failure": "inconclusive",
                },
                "fast_mode_state": {
                    "rule": "constant",
                    "value": "off",
                    "failure": "inconclusive",
                },
            },
        )
        self.assertEqual(
            set(init_contract["required_fields"]),
            {
                "type",
                "subtype",
                "cwd",
                "permissionMode",
                "tools",
                "mcp_servers",
                "slash_commands",
                "skills",
                "plugins",
                "model",
                "claude_code_version",
                "apiKeySource",
            },
        )
        self.assertEqual(
            schema["launch_profiles"],
            {
                "named-direct": {
                    "permission_mode": "dontAsk",
                    "runtime_cwd": "host-workspace",
                    "tools": ["Bash", "Glob", "Grep", "Read"],
                },
                "helper-linux": {
                    "permission_mode": "dontAsk",
                    "runtime_cwd": "/workspace",
                    "tools": ["Read"],
                },
                "helper-darwin": {
                    "permission_mode": "default",
                    "runtime_cwd": "host-workspace",
                    "tools": ["Glob", "Grep", "Read"],
                },
            },
        )
        self.assertEqual(
            init_contract["field_contracts"]["cwd"],
            {
                "rule": "exact_expected_runtime_cwd",
                "binding_field": "expected_runtime_cwd",
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        self.assertEqual(
            init_contract["field_contracts"]["tools"],
            {
                "rule": "duplicate_free_exact_runtime_binding_launch_profile_set",
                "profile_field": "tools",
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        self.assertEqual(
            init_contract["field_contracts"]["permissionMode"],
            {
                "rule": "exact_runtime_binding_launch_profile",
                "profile_field": "permission_mode",
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        self.assertEqual(
            init_contract["field_contracts"]["claude_code_version"],
            {
                "rule": "exact_cli_argument",
                "argument": "claude_code_version",
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        self.assertEqual(
            init_contract["field_contracts"]["apiKeySource"],
            {
                "rule": "exact_runtime_binding",
                "binding_field": "api_key_source",
                "accepted_values": ["ANTHROPIC_API_KEY", "none"],
                "malformed_failure": "inconclusive",
                "mismatch_failure": "blocked",
            },
        )
        identities = schema["model_identity"]
        self.assertEqual(
            identities["claude-opus-4-8"]["accepted_model_usage_keys"],
            ["claude-opus-4-8", "claude-opus-4.8"],
        )
        self.assertEqual(
            identities["claude-opus-4-7"]["accepted_model_usage_keys"],
            ["claude-opus-4-7", "claude-opus-4.7"],
        )
        accepted_auxiliary_keys = set(schema["accepted_auxiliary_model_usage_keys"])
        self.assertEqual(
            accepted_auxiliary_keys,
            {"claude-haiku-4-5-20251001"},
        )
        all_primary_keys = {
            key
            for identity in identities.values()
            for key in identity["accepted_model_usage_keys"]
        }
        allowed_terminal_fields = set(schema["terminal_result"]["required_fields"])
        allowed_terminal_fields.update(schema["terminal_result"]["optional_fields"])
        optional_contracts = schema["terminal_result"]["optional_field_contracts"]
        self.assertEqual(
            set(schema["terminal_result"]["optional_fields"]),
            set(optional_contracts),
        )
        self.assertEqual(
            optional_contracts["stop_reason"],
            {
                "rule": "enum",
                "accepted_values": [None, "end_turn"],
                "failure": "blocked",
            },
        )
        self.assertEqual(optional_contracts["structured_output"]["rule"], "null")

        def optional_value_is_valid(rule: str, value: object, contract: dict) -> bool:
            if rule == "nonnegative_integer":
                return type(value) is int and value >= 0
            if rule == "positive_integer":
                return type(value) is int and value > 0
            if rule == "nonnegative_finite_number":
                return (
                    type(value) in (int, float) and math.isfinite(value) and value >= 0
                )
            if rule == "nonempty_string":
                return isinstance(value, str) and bool(value.strip())
            if rule == "object":
                return isinstance(value, dict)
            if rule == "enum":
                return value in contract["accepted_values"]
            if rule == "null":
                return value is None
            if rule == "explicitly_empty":
                return (
                    value is None
                    or value in ("", [], {})
                    or (isinstance(value, str) and not value.strip())
                )
            if rule == "null_or_whitespace_string":
                return value is None or (isinstance(value, str) and not value.strip())
            if rule == "empty_array":
                return value == []
            self.fail(f"unknown optional-field rule: {rule}")

        observed = {}
        for case in schema["contract_cases"]:
            identity = identities[case["requested_model"]]
            requested_keys = set(identity["accepted_model_usage_keys"])
            observed_model_keys = set(case["model_usage_keys"])
            other_primary_keys = all_primary_keys - requested_keys
            unknown_model_keys = observed_model_keys - (
                requested_keys | other_primary_keys | accepted_auxiliary_keys
            )
            unknown_fields = (
                set(case["extra_terminal_fields"]) - allowed_terminal_fields
            )
            optional_failures = set()
            for field, value in case["optional_terminal_values"].items():
                contract = optional_contracts.get(field)
                if contract is None:
                    optional_failures.add("inconclusive")
                elif not optional_value_is_valid(contract["rule"], value, contract):
                    optional_failures.add(contract["failure"])

            blocked_evidence = any(
                (
                    case["init_model"] != identity["init_model"],
                    bool(observed_model_keys.intersection(other_primary_keys)),
                    not observed_model_keys.intersection(requested_keys),
                    "blocked" in optional_failures,
                )
            )
            inconclusive_evidence = any(
                (
                    bool(unknown_fields),
                    bool(unknown_model_keys),
                    "inconclusive" in optional_failures,
                    bool(optional_failures - {"blocked", "inconclusive"}),
                )
            )
            if blocked_evidence and inconclusive_evidence:
                outcome = "inconclusive"
            elif inconclusive_evidence:
                outcome = "inconclusive"
            elif blocked_evidence:
                outcome = "blocked"
            else:
                outcome = "accept"
            observed[case["name"]] = outcome
            self.assertEqual(outcome, case["expected"], case["name"])

        self.assertEqual(observed["reviewed_terminal_alias"], "accept")
        self.assertEqual(observed["reviewed_auxiliary_model"], "accept")
        self.assertEqual(observed["silent_model_fallback"], "blocked")
        self.assertEqual(observed["mixed_primary_model_substitution"], "blocked")
        self.assertEqual(observed["unknown_model_usage_key"], "inconclusive")
        self.assertEqual(
            observed["mixed_primary_and_unknown_model_evidence"],
            "inconclusive",
        )
        self.assertEqual(observed["truncated_stop_reason"], "blocked")
        self.assertEqual(observed["unexpected_structured_output"], "inconclusive")
        self.assertEqual(observed["invalid_optional_metric"], "inconclusive")
        self.assertEqual(observed["unknown_error_field"], "inconclusive")
        for anchor in (
            "equals the requested concrete model string exactly",
            "baseline-reviewed aliases for requested",
            "The only baseline-reviewed auxiliary key",
            "with only or with both a `claude-opus-4-7` key",
            "`stop_reason`, when present, is exactly `null` or `end_turn`",
            "Any other value—including `max_tokens`",
            "`structured_output`, when present, is exactly `null`",
            "closed allowlists for init, every intermediate event family, and every terminal variant",
            "Any other field, including an unknown error-bearing field",
        ):
            self.assertIn(anchor, canonical)

        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        for content in (skill, contracts, canonical):
            self.assertIn(">=2.1.211,<3.0.0", content)
            self.assertIn("signed per-version manifest", content)
            self.assertNotIn("exact Claude Code `2.1.212`", content)
            self.assertNotIn("exactly `2.1.212`", content)
        self.assertIn("claude-stream-schema.json", canonical)
        self.assertIn("binds the selected version", canonical)
        self.assertIn("--authentication-source", canonical)
        self.assertNotIn("--api-key-source", canonical)
        self.assertIn("legacy", canonical.lower())
        self.assertIn("extended", canonical.lower())
        baseline_sentence = (
            "Claude Code `2.1.212` is the audited per-version stream-schema "
            "baseline, not a global eligibility pin."
        )
        for content in (skill, contracts, canonical):
            self.assertIn(baseline_sentence, content)
        self.assertIn("`strict-version-and-launch-profiles`", canonical)
        self.assertIn("claude-stream-compatibility.json", skill)
        self.assertIn("stream-profile digest evidence", contracts)
        self.assertNotIn("require exactly Claude Code `2.1.212`", canonical)

    def test_unsupported_mismatched_pr_stays_effective_double_but_not_ready(
        self,
    ) -> None:
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        documents = [agents_policy, readiness, skill, templates, contracts, probes]
        if CI_PROFILE == "canonical":
            documents.append((REPO_ROOT / "README.md").read_text(encoding="utf-8"))

        causal_contract = "For the same mismatch on an already unsupported PR, keep `requested: triple`, `effective: double`, and report readiness `blocked-authorization`; do not treat the mismatch as making the already-unavailable lane triple-inconclusive or as permitting readiness to continue."
        for content in documents:
            self.assertIn(causal_contract, content)

    def test_main_workflow_checks_existing_pr_head_before_local_lanes(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )

        head_preflight = "compare it with the intended `head_sha` before creating or running any local lane"
        run_codex = "Run the fresh-context Codex lane"
        for content in (skill, readiness):
            self.assertIn("selected existing PR", content)
            self.assertIn("single, double, triple", content)
        self.assertIn(
            "explicit-range-only standalone single/double with no selected PR and the proven no-PR path have no PR-head comparison",
            skill,
        )
        self.assertIn(
            "No comparison exists for explicit-range-only standalone single/double with no selected PR, or for the authenticated no-PR path",
            readiness,
        )
        self.assertIn(head_preflight, skill)
        self.assertLess(skill.index(head_preflight), skill.index(run_codex))
        self.assertIn(
            "PR/full-workflow request or any standalone named review request",
            skill,
        )
        self.assertIn(
            "PR/full-workflow request or standalone named review associated with an existing PR",
            readiness,
        )
        self.assertIn(
            "A standalone triple or PR-specific request may perform the narrow read-only PR lookup",
            readiness,
        )
        self.assertLess(
            probes.index("Any existing PR with current `headRefOid != head_sha`"),
            probes.index("Only after an existing PR is head-aligned"),
        )

    def test_named_lanes_block_lazy_fetch_before_reviewer_launch(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts):
            self.assertIn("GIT_NO_LAZY_FETCH=1", content)
            self.assertIn("GIT_TERMINAL_PROMPT=0", content)
            self.assertIn("locally complete", content)
        self.assertIn("non-rendering plumbing", contracts)
        self.assertIn("never let the reviewer trigger an on-demand fetch", skill)
        self.assertIn("forbid `fetch`, `pull`", templates)
        self.assertNotIn("prepared full diff", contracts)

    def test_named_lanes_use_the_narrow_shipped_guard_before_launch(self) -> None:
        agents = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for content in (agents, skill, contracts, canonical):
            self.assertIn("scripts/named_lane_guard", content)
            self.assertIn("validate-worktree", content)
        for anchor in (
            "stable tracked source symlinks",
            "absolute targets",
            "transitive escape",
            "unstable or mismatched tracked symlinks",
            "ordinary non-symlink regular file",
            "without reading an escaping target",
            "blocked-safety",
        ):
            self.assertIn(anchor, contracts)
        for overreach in (
            "raw-object workspace",
            "immutable guidance snapshots",
            "general secret/content scan",
        ):
            self.assertIn(overreach, contracts)
        self.assertIn(
            "Do not expand that guard into",
            contracts,
        )
        for content in (skill, contracts, canonical):
            self.assertIn("30-second", content)
            self.assertIn("4,096", content)
            self.assertIn("16 KiB", content)
            self.assertIn("64 MiB", content)

    def test_named_lane_runtime_import_closure_matches_control_manifest(self) -> None:
        guard = SCRIPTS / "named_lane_guard"

        def loaded_bound_modules(*profile_args: str) -> list[str]:
            probe = "\n".join(
                (
                    "import json",
                    "import pathlib",
                    "import sys",
                    f"guard = pathlib.Path({str(guard)!r})",
                    f"sys.argv = [str(guard), *{list(profile_args)!r}]",
                    "namespace = {'__name__': '_guard_contract_probe', "
                    "'__file__': str(guard)}",
                    "exec(compile(guard.read_bytes(), str(guard), 'exec'), namespace)",
                    "print(json.dumps(sorted(name for name in sys.modules "
                    "if name == 'review_runtime' "
                    "or name.startswith('review_runtime.') "
                    "or name == 'validate_claude_stream')))",
                )
            )
            completed = subprocess.run(
                (sys.executable, "-I", "-B", "-S", "-c", probe),
                cwd=REPO_ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            return json.loads(completed.stdout)

        self.assertEqual(
            loaded_bound_modules(),
            ["review_runtime", "review_runtime.common", "review_runtime.named_lane"],
        )
        self.assertEqual(
            loaded_bound_modules("preflight-claude"),
            [
                "review_runtime",
                "review_runtime.claude_capabilities",
                "review_runtime.claude_linux",
                "review_runtime.claude_provenance",
                "review_runtime.claude_refresh_lock",
                "review_runtime.claude_stream_contract",
                "review_runtime.claude_version_policy",
                "review_runtime.common",
                "review_runtime.named_claude_preflight",
            ],
        )
        self.assertEqual(
            loaded_bound_modules("validate-claude-stream"),
            [
                "review_runtime",
                "review_runtime.claude_capabilities",
                "review_runtime.claude_linux",
                "review_runtime.claude_provenance",
                "review_runtime.claude_refresh_lock",
                "review_runtime.claude_stream_contract",
                "review_runtime.claude_version_policy",
                "review_runtime.common",
                "validate_claude_stream",
            ],
        )
        self.assertEqual(
            loaded_bound_modules("classify-review-result"),
            ["review_runtime", "review_runtime.review_result"],
        )

        entrypoint = guard.read_text(encoding="utf-8")
        for anchor in (
            "_DEFAULT_RUNTIME_SOURCES",
            "_CLAUDE_PREFLIGHT_SOURCES",
            "_CLAUDE_STREAM_RUNTIME_SOURCES",
            "_CLAUDE_STREAM_VALIDATOR_SOURCES",
            "_REVIEW_RESULT_SOURCES",
            "_load_default_entrypoint",
            "_load_claude_preflight_entrypoint",
            "_load_claude_stream_validator_entrypoint",
            "_load_review_result_entrypoint",
            '"review_runtime.claude_refresh_lock"',
            '"claude_refresh_lock.py"',
            '"review_runtime.claude_linux"',
            '"claude_linux.py"',
            '"CLAUDE_RELEASE_KEY_BYTES"',
            '"COMPATIBILITY_JSON_BYTES"',
            '"BASELINE_SCHEMA_BYTES"',
            '"PROFILE_SCHEMA_BYTES"',
            '"CAPABILITY_SOURCE_BYTES"',
            '"FD_EXEC_BYTES"',
            '"fd_exec.py"',
            'argv[0] == "preflight-claude"',
            'argv[0] == "validate-claude-stream"',
            'argv[0] == "classify-review-result"',
        ):
            self.assertIn(anchor, entrypoint)
        self.assertNotIn("sys.path.insert", entrypoint)
        self.assertNotIn("from review_runtime", entrypoint)

    def test_named_claude_profiles_consume_guard_bound_companion_bytes(
        self,
    ) -> None:
        guard = (SCRIPTS / "named_lane_guard").read_text(encoding="utf-8")
        provenance = (SCRIPTS / "review_runtime/claude_provenance.py").read_text(
            encoding="utf-8"
        )
        common = (SCRIPTS / "review_runtime/common.py").read_text(encoding="utf-8")
        validator = (SCRIPTS / "validate_claude_stream.py").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for binding in (
            "CLAUDE_RELEASE_KEY_BYTES",
            "COMPATIBILITY_JSON_BYTES",
            "BASELINE_SCHEMA_BYTES",
            "PROFILE_SCHEMA_BYTES",
            "CAPABILITY_SOURCE_BYTES",
        ):
            self.assertIn(f'"{binding}"', guard)
        self.assertIn("byte_bindings", guard)
        self.assertIn("_CompanionBinding = bytes", guard)
        self.assertIn('"FD_EXEC_BYTES"', guard)
        self.assertIn("FD_EXEC_BYTES: bytes | None = None", common)
        self.assertIn("bound_launcher = FD_EXEC_BYTES", common)
        self.assertIn(
            '"-I",\n            "-B",\n            "-S",\n            "-c"', common
        )
        descriptor_launcher = common.split("bound_launcher = FD_EXEC_BYTES", 1)[
            1
        ].split("def _descriptor_exec_error", 1)[0]
        self.assertNotIn("str(launcher)", descriptor_launcher.split("else:", 1)[1])
        companion_validator = guard.split("def _validate_bound_companion(", 1)[1].split(
            "def _guard_companions(", 1
        )[0]
        self.assertIn("return payload", companion_validator)
        self.assertNotIn("return identity", companion_validator)
        companion_guard = guard.split("def _guard_companions(", 1)[1].split(
            "def _load_default_entrypoint(", 1
        )[0]
        self.assertNotIn("actual_binding[0]", companion_guard)
        self.assertNotIn("actual_binding[1]", companion_guard)
        self.assertIn("actual_binding != expected_binding", companion_guard)
        self.assertNotIn("st_mtime", companion_guard)
        self.assertNotIn("st_ctime", companion_guard)

        self.assertIn("CLAUDE_RELEASE_KEY_BYTES: bytes | None = None", provenance)
        self.assertIn("bound_release_key = CLAUDE_RELEASE_KEY_BYTES", provenance)
        self.assertIn("if bound_release_key is None:", provenance)
        self.assertIn("release_key = bytes(bound_release_key)", provenance)
        self.assertEqual(provenance.count("CLAUDE_RELEASE_KEY_PATH.read_bytes()"), 1)

        for binding in (
            "COMPATIBILITY_JSON_BYTES",
            "BASELINE_SCHEMA_BYTES",
            "PROFILE_SCHEMA_BYTES",
            "CAPABILITY_SOURCE_BYTES",
        ):
            self.assertIn(f"{binding}: bytes | None = None", validator)
        self.assertIn("bound_payloads = (", validator)
        self.assertIn(
            "if all(payload is None for payload in bound_payloads):", validator
        )
        self.assertIn(
            "elif any(payload is None for payload in bound_payloads):", validator
        )
        self.assertIn("_load_bound_stream_contract(", validator)

        for anchor in (
            "retains those exact immutable bytes",
            "gives the same buffers to the consumer",
            "must not reopen a companion path after final validation",
            "compares only complete bytes across the two reads",
            "does not compare dev/ino, `mtime`, or `ctime` across them",
            "same-content ordinary-file replacement is allowed",
            "same-inode and same-size content change",
            "CLAUDE_RELEASE_KEY_BYTES",
            "COMPATIBILITY_JSON_BYTES",
            "BASELINE_SCHEMA_BYTES",
            "PROFILE_SCHEMA_BYTES",
            "CAPABILITY_SOURCE_BYTES",
            "FD_EXEC_BYTES",
            "isolated `-I -B -S -c` bootstrap",
            "never reopen the `review_runtime/fd_exec.py` path",
            "consumers do not reopen those companions after final revalidation",
        ):
            self.assertIn(anchor, contracts)

    def test_self_policy_migration_uses_an_external_trusted_control_plane(
        self,
    ) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        agents = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        reviewer = (policy_scope_root / "agents/reviewer.toml").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for content in (agents, reviewer, skill, contracts, templates):
            normalized = content.lower()
            self.assertIn("candidate-head markdown", normalized)
            self.assertIn("review subject", normalized)
            self.assertIn("candidate-head python", normalized)
            self.assertIn("trusted", normalized)
        for content in (agents, skill, contracts, templates):
            self.assertIn("absolute", content)
            self.assertIn("version", content)
            self.assertIn("SHA-256", content)
        self.assertIn("independently trusted bundle pinned outside", agents)
        self.assertIn("prior trusted policy", agents)
        self.assertIn("merge and release", contracts)
        self.assertIn("activate the new guard", contracts)
        self.assertIn("Ordinary implementation tests", contracts)
        manifest_paths = (
            "agents/reviewer.toml",
            "skills/review-orchestration-playbook/SKILL.md",
            "skills/review-orchestration-playbook/references/base-only-retarget-state-machine.json",
            "skills/review-orchestration-playbook/references/canonical-claude-lane.md",
            "skills/review-orchestration-playbook/references/claude-2.1.212-stream-schema.json",
            "skills/review-orchestration-playbook/references/claude-runtime-trust.md",
            "skills/review-orchestration-playbook/references/claude-stream-compatibility.json",
            "skills/review-orchestration-playbook/references/claude-stream-schema.json",
            "skills/review-orchestration-playbook/references/egress-consent.md",
            "skills/review-orchestration-playbook/references/github-codex-evidence-authority.md",
            "skills/review-orchestration-playbook/references/github-pr-probes.md",
            "skills/review-orchestration-playbook/references/pr-readiness.md",
            "skills/review-orchestration-playbook/references/review-lane-contracts.md",
            "skills/review-orchestration-playbook/references/review-prompt-templates.md",
            "skills/review-orchestration-playbook/scripts/named_claude_preflight",
            "skills/review-orchestration-playbook/scripts/named_lane_guard",
            "skills/review-orchestration-playbook/scripts/review_runtime/__init__.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_capabilities.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_code_release.asc",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_linux.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_provenance.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_refresh_lock.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_stream_contract.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_version_policy.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/common.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/fd_exec.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/named_claude_preflight.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/named_lane.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/review_result.py",
            "skills/review-orchestration-playbook/scripts/validate_claude_stream.py",
        )
        self.assertEqual(
            manifest_paths,
            tuple(sorted(manifest_paths, key=lambda value: value.encode("utf-8"))),
        )
        for relative_path in manifest_paths:
            payload = (policy_scope_root / relative_path).read_bytes()
            for marker in (b"<<<<<<< ", b"=======\n", b">>>>>>> "):
                self.assertNotIn(marker, payload, relative_path)
        manifest_clause = (
            "; ".join(f"`{path}`" for path in manifest_paths[:-1])
            + f"; and `{manifest_paths[-1]}`."
        )
        self.assertIn(manifest_clause, contracts)

        outcome_policy_paths = (
            "skills/review-orchestration-playbook/references/base-only-retarget-state-machine.json",
            "skills/review-orchestration-playbook/references/egress-consent.md",
            "skills/review-orchestration-playbook/references/github-codex-evidence-authority.md",
            "skills/review-orchestration-playbook/references/github-pr-probes.md",
            "skills/review-orchestration-playbook/references/pr-readiness.md",
            "skills/review-orchestration-playbook/scripts/review_runtime/review_result.py",
        )

        def manifest_digest(overrides: dict[str, bytes] | None = None) -> str:
            replacements = overrides or {}
            records = []
            for relative_path in manifest_paths:
                payload = replacements.get(
                    relative_path,
                    (policy_scope_root / relative_path).read_bytes(),
                )
                records.append(
                    f"{hashlib.sha256(payload).hexdigest()}  {relative_path}\n".encode(
                        "utf-8"
                    )
                )
            return hashlib.sha256(b"".join(records)).hexdigest()

        baseline_manifest_digest = manifest_digest()
        for relative_path in outcome_policy_paths:
            original = (policy_scope_root / relative_path).read_bytes()
            self.assertNotEqual(
                manifest_digest({relative_path: original + b"\0"}),
                baseline_manifest_digest,
                relative_path,
            )
        for anchor in (
            "publisher-provided release identifier or frozen commit ID",
            "canonical UTF-8 manifest",
            "<lowercase-file-sha256><two ASCII spaces><relative-path><LF>",
            "contains both `agents/` and `skills/` as the single bundle root",
            "agents/reviewer.toml",
            "skills/review-orchestration-playbook/SKILL.md",
            "skills/review-orchestration-playbook/references/claude-2.1.212-stream-schema.json",
            "skills/review-orchestration-playbook/references/claude-stream-compatibility.json",
            "skills/review-orchestration-playbook/references/claude-stream-schema.json",
            "skills/review-orchestration-playbook/references/base-only-retarget-state-machine.json",
            "skills/review-orchestration-playbook/references/egress-consent.md",
            "skills/review-orchestration-playbook/references/github-codex-evidence-authority.md",
            "skills/review-orchestration-playbook/references/github-pr-probes.md",
            "skills/review-orchestration-playbook/references/pr-readiness.md",
            "skills/review-orchestration-playbook/references/review-lane-contracts.md",
            "skills/review-orchestration-playbook/references/review-prompt-templates.md",
            "skills/review-orchestration-playbook/references/canonical-claude-lane.md",
            "skills/review-orchestration-playbook/references/claude-runtime-trust.md",
            "skills/review-orchestration-playbook/scripts/named_claude_preflight",
            "skills/review-orchestration-playbook/scripts/named_lane_guard",
            "skills/review-orchestration-playbook/scripts/review_runtime/__init__.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_capabilities.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_code_release.asc",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_linux.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_provenance.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_refresh_lock.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_stream_contract.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/claude_version_policy.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/named_claude_preflight.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/named_lane.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/review_result.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/common.py",
            "skills/review-orchestration-playbook/scripts/review_runtime/fd_exec.py",
            "review_runtime.common.FD_EXEC_BYTES",
            "isolated `-I -B -S -c` bootstrap",
            "never reopen the `review_runtime/fd_exec.py` path",
            "skills/review-orchestration-playbook/scripts/validate_claude_stream.py",
            "immediately before each guard, Claude preflight, stream-validator, Claude-launch, and Codex-spawn use",
            "Recompute it after each lane",
            "exact bytes must match the manifest entry",
            "exact three-source bound-source raw loader",
            "default guard code-origin/import boundary",
            "exact nine-source closure",
            "Both Linux support modules are mandatory",
            "Neither profile may widen its control-plane closure to `review_runtime.workspace`, `review_runtime.prompt`, or `review_runtime.synthetic_tokens`",
            "preflight-claude",
            "validate-claude-stream",
            "classify-review-result",
        ):
            self.assertIn(anchor, contracts)
        self.assertNotIn(
            "use the repo-local playbook from the frozen review head",
            agents,
        )

    def test_named_claude_control_plane_profiles_have_distinct_boundaries(
        self,
    ) -> None:
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        boundaries = contracts.split(
            "### Claude Control-Plane Sequence And Boundaries",
            1,
        )[1].split("## GitHub Codex Lane Contract", 1)[0]

        formal_prefix = (
            "<trusted-python-absolute-path> -I -B -S "
            "<trusted-bundle-absolute-path>/skills/review-orchestration-playbook/"
            "scripts/named_lane_guard"
        )
        for profile in (
            "preflight-claude",
            "validate-claude-stream",
            "classify-review-result",
        ):
            self.assertIn(f"{formal_prefix} {profile}", contracts)
        for anchor in (
            "exact three-source bound-source raw loader",
            "default eager runtime closure",
            "exact two-source closure",
            "review_runtime.review_result",
            "same-content ordinary-file replacement is harmless",
            "review_runtime.claude_refresh_lock",
            "review_runtime.claude_linux",
            "review_runtime.claude_provenance",
            "review_runtime.claude_stream_contract",
            "review_runtime.claude_version_policy",
            "review_runtime.claude_capabilities",
            "review_runtime.named_claude_preflight",
            "claude_code_release.asc",
            "standalone validator plus its exact required runtime-source closure",
            "stream compatibility profile, audited schema baseline, versioned profile schema, and capability-contract source",
            "same bounded bytes retained through final validation",
            "must not reopen a companion path after final validation",
            "compatibility wrapper",
            "never the formal named-lane or self-policy-migration entry",
            "Neither profile may use the candidate wrapper",
            "Do not inherit ambient `HOME`",
            "pwd.getpwuid(os.getuid())",
            "without treating directory `mtime`, `ctime`, or child churn",
            "fixed `--authentication-source local-login`",
            "child's exact `returncode` from the guard's machine result",
            "8 MiB stream cap",
            "64 MiB stdout cap",
        ):
            self.assertIn(anchor, contracts)

        ordered_controls = (
            "trusted bundle digest binds",
            "selects and publisher-verifies",
            "final clean/safety launch gate",
            "launches that snapshot as its direct child",
            "runs only after that parent receipt comparison",
        )
        positions = [boundaries.index(anchor) for anchor in ordered_controls]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("default guard code-origin/import boundary", contracts)
        self.assertIn(
            "Neither profile may use the candidate wrapper, ordinary bundle-path "
            "import resolution, a candidate-head source/schema, or a path re-read "
            "in place of the bound bytes.",
            contracts,
        )

    def test_formal_guard_paths_resolve_from_manifest_bundle_root(self) -> None:
        self.assertTrue((SKILL_SCOPE_ROOT / "agents").is_dir())
        self.assertTrue((SKILL_SCOPE_ROOT / "skills").is_dir())
        guard_relative = pathlib.Path(
            "skills/review-orchestration-playbook/scripts/named_lane_guard"
        )
        guard = SKILL_SCOPE_ROOT / guard_relative
        self.assertEqual(guard, SCRIPTS / "named_lane_guard")
        self.assertTrue(guard.is_file())

        expected = (
            "<trusted-bundle-absolute-path>/"
            "skills/review-orchestration-playbook/scripts/named_lane_guard"
        )
        flattened = "<trusted-bundle-absolute-path>/scripts/named_lane_guard"
        for document in (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/canonical-claude-lane.md",
        ):
            content = document.read_text(encoding="utf-8")
            self.assertNotIn(flattened, content)
            formal_lines = [
                line
                for line in content.splitlines()
                if "<trusted-bundle-absolute-path>" in line
                and "named_lane_guard" in line
            ]
            self.assertTrue(formal_lines)
            for line in formal_lines:
                self.assertIn(expected, line)

    def test_repo_visible_git_includes_are_blocked_without_expansion(self) -> None:
        agents = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (agents, skill, contracts, canonical):
            self.assertIn("`include.path`", content)
            self.assertIn("`includeIf.*.path`", content)
            self.assertIn("`blocked-safety`", content)
            lowered = content.lower()
            self.assertTrue(
                "includes disabled" in lowered or "includes stay disabled" in lowered
            )
        self.assertIn("even when its condition is inactive", contracts)
        self.assertIn(
            "never accepts included values as safety configuration", contracts
        )
        self.assertIn("provide no no-read guarantee", contracts)
        self.assertIn("every raw gitlink", contracts)
        self.assertIn("global pathspecs apply", contracts)
        for retired_included_config_contract in (
            "effective included Git configuration",
            "effective included `core.fsmonitor`",
            "earlier included path overridden",
        ):
            for content in (skill, contracts, canonical):
                self.assertNotIn(retired_included_config_contract, content)
        for anchor in (
            "_validate_git_config_includes",
            'lower_key == b"include.path"',
            'lower_key.startswith(b"includeif.")',
            '"--no-includes"',
        ):
            self.assertIn(anchor, runtime)

    def test_codex_reviewer_git_is_bound_to_the_sanitized_prefix(self) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        reviewer = (policy_scope_root / "agents/reviewer.toml").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for content in (reviewer, skill, contracts, templates):
            self.assertIn("exact sanitized Git argv prefix", content)
            self.assertIn("`/usr/bin/env -i`", content)
            self.assertIn("trusted `PATH`", content)
            self.assertIn("`LANG`/`LC_*`", content)
            self.assertIn("`PAGER`", content)
            self.assertIn("`GIT_*`", content)
            self.assertIn("resolved trusted Git executable", content)
            self.assertIn("safe `-c` flags", content)
            self.assertIn("-C", content)
            self.assertIn("--no-ext-diff --no-textconv", content)
        self.assertIn("never run bare `git`", reviewer)
        self.assertIn("forbid bare `git`", templates)
        self.assertIn("another worktree are forbidden", skill)
        exact_prefix_contract = contracts[
            contracts.index(
                "for Codex, the exact sanitized Git argv prefix"
            ) : contracts.index("The parent must not:")
        ]
        for anchor in (
            "`/usr/bin/env -i`",
            "recorded trusted `PATH`",
            "fixed `LANG`/`LC_ALL`",
            "`GIT_ASKPASS=/usr/bin/false`",
            "`GIT_ATTR_NOSYSTEM=1`",
            "`GIT_CEILING_DIRECTORIES=<absolute-clean-worktree-parent>`",
            "`GIT_CONFIG_GLOBAL=/dev/null`",
            "`GIT_CONFIG_SYSTEM=/dev/null`",
            "`GIT_CONFIG_NOSYSTEM=1`",
            "`GIT_NO_LAZY_FETCH=1`",
            "`GIT_TERMINAL_PROMPT=0`",
            "`GIT_NO_REPLACE_OBJECTS=1`",
            "`GIT_OPTIONAL_LOCKS=0`",
            "`PAGER=cat`",
            "`GIT_PAGER=cat`",
            "`--no-pager",
            "core.commitGraph=false",
            "core.multiPackIndex=false",
            "core.fsmonitor=false",
            "core.fileMode=true",
            "core.hooksPath=/dev/null",
            "core.attributesFile=/dev/null",
            "diff.external=",
            "color.ui=false",
            "-C <absolute-clean-worktree>",
        ):
            self.assertIn(anchor, exact_prefix_contract)

    def test_named_lane_pristine_guard_covers_hidden_ignored_and_gitlinks(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")
        policy = (skill, contracts, canonical)

        for content in policy:
            for anchor in (
                "assume-unchanged",
                "skip-worktree",
                "ignored",
                "uninitialized",
                "materialized",
            ):
                with self.subTest(anchor=anchor):
                    self.assertIn(anchor, content)
        self.assertIn("absent or empty uninitialized gitlink", skill)
        self.assertIn("path is absent or is an empty directory", contracts)
        self.assertIn("may consume only that exact status record", contracts)
        self.assertIn("every materialized or initialized submodule", canonical)
        self.assertIn("per-name boolean precedence", canonical)
        self.assertIn("repeated `submodule.active` pathspec", contracts)
        self.assertIn("explicit per-name false", contracts.lower())
        self.assertIn("global pathspecs apply to every raw gitlink", contracts)
        self.assertIn("forces `core.fileMode=true`", contracts)
        self.assertIn("forces `core.commitGraph=false`", contracts)
        self.assertIn("`core.multiPackIndex=false`", contracts)
        self.assertIn("`diff.external`", contracts)
        self.assertIn("`diff.<driver>.command`", contracts)
        self.assertIn("`diff.<driver>.textconv`", contracts)
        self.assertIn("both `--no-ext-diff` and `--no-textconv`", contracts)

        for anchor in (
            "_validate_index_flags",
            '"ls-files", "--cached", "--full-name", "-v", "-z", "--"',
            '"--ignored=matching"',
            '"--ignore-submodules=none"',
            '"--no-renames"',
            'entry[0] == "160000"',
            "_validate_initialized_submodules",
            'r"^submodule\\..*\\.path$"',
            "_effective_submodule_active_pathspecs",
            "_match_submodule_active_pathspecs",
            '"core.fileMode=true"',
            '"core.commitGraph=false"',
            '"core.multiPackIndex=false"',
            "_validate_executable_git_config",
            "_validate_materialized_gitlink",
            "_status_has_disallowed_changes",
        ):
            self.assertIn(anchor, runtime)

    def test_named_lane_guard_is_property_scoped_not_a_content_snapshot(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        self.assertIn(
            "compare only properties relevant to object completeness, checkout safety, clean state, or reviewer safety",
            skill,
        )
        self.assertIn("Keep the guard property-scoped", contracts)
        self.assertIn("must not treat `mtime`, `ctime`", contracts)
        self.assertIn("must not snapshot or rehash ordinary file contents", contracts)
        self.assertIn("does not compare `mtime`/`ctime`", canonical)
        self.assertIn("or snapshot ordinary file contents", canonical)
        for overstrict_implementation in (
            "st_mtime",
            "st_ctime",
            '"hash-object"',
        ):
            self.assertNotIn(overstrict_implementation, runtime)
        self.assertIn('("cat-file", "--batch")', runtime)
        self.assertIn("SYMLINK_COUNT_LIMIT", runtime)
        self.assertIn("SYMLINK_BATCH_OUTPUT_LIMIT_BYTES", runtime)
        self.assertNotIn('("cat-file", "blob"', runtime)

    def test_named_lane_guard_blocks_effective_fsmonitor_before_reviewer_git(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            self.assertIn("`core.fsmonitor`", content)
            self.assertIn("Git-false", content)
            self.assertIn("path", content)
            self.assertIn("reviewer Git", content)
        self.assertIn("A built-in daemon (`true`)", contracts)
        self.assertIn("a no-value declaration", contracts)
        self.assertIn(
            "direct local/per-worktree precedence remains effective", contracts
        )
        self.assertNotIn("effective included `core.fsmonitor`", contracts)
        self.assertNotIn("an earlier included path overridden by a later", contracts)
        for anchor in (
            "_validate_core_fsmonitor_config",
            '"core.fsmonitor=false"',
            "neutralize_fsmonitor=False",
            '"config", "--no-includes", "--null", "--get", "core.fsmonitor"',
        ):
            self.assertIn(anchor, runtime)

    def test_direct_claude_guard_has_minimal_environment_and_output_paths(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            for anchor in (
                "real `HOME`",
                "PATH",
                "locale/UI",
                "proxy",
                "CA",
                "Claude/Anthropic",
                "cloud-provider",
                "dynamic-loader",
                "tool-control",
            ):
                with self.subTest(anchor=anchor):
                    self.assertIn(anchor, content)
            self.assertIn("--inherit-node-extra-ca-certs", content)
            self.assertIn("Ambient `NODE_EXTRA_CA_CERTS`", content)
        for anchor in (
            "pwd.getpwuid(os.getuid())",
            "GIT_NO_LAZY_FETCH=1",
            "GIT_TERMINAL_PROMPT=0",
            "GIT_NO_REPLACE_OBJECTS=1",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "GIT_OPTIONAL_LOCKS=0",
            "GIT_ASKPASS=/usr/bin/false",
            "GIT_ATTR_NOSYSTEM=1",
            "GIT_PAGER=cat",
            "PAGER=cat",
            "ambient Claude or Anthropic API/config variable",
        ):
            self.assertIn(anchor, canonical)
        for anchor in (
            "caller supplies a lane-unique",
            "canonical real parent directory",
            "absent, non-symlink leaf",
        ):
            self.assertIn(anchor, skill)
        self.assertIn("already-canonical real directory", canonical)
        self.assertIn("current-user-owned", canonical)
        self.assertIn("exact-mode-`0700`", canonical)
        self.assertIn("cooperatively exclude every other same-UID writer", canonical)
        self.assertIn("no portable conditional unlink", canonical)
        self.assertIn("explicit commit point", canonical)
        self.assertIn("leaf must be absent and non-symlink", canonical)
        self.assertIn("open directory descriptor", canonical)
        self.assertIn("(st_dev, st_ino)", canonical)

        self.assertIn("CLAUDE_ENV_PASSTHROUGH_KEYS", runtime)
        self.assertIn("pwd.getpwuid(os.getuid())", runtime)
        self.assertIn(
            "env=_claude_environment(root, inherit_node_extra_ca_certs)",
            runtime,
        )
        self.assertNotIn("env=dict(os.environ)", runtime)
        for key in (
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "COLORTERM",
            "NO_COLOR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
        ):
            with self.subTest(key=key):
                self.assertIn(f'"{key}"', runtime)
        self.assertIn('os.environ.get("NODE_EXTRA_CA_CERTS")', runtime)
        self.assertIn('"--inherit-node-extra-ca-certs"', runtime)
        self.assertIn("_validate_node_extra_ca_certs", runtime)
        self.assertIn("_OutputTarget", runtime)
        self.assertIn("dir_fd=target.parent_fd", runtime)
        self.assertIn("_revalidate_output_parent(stdout)", runtime)
        self.assertIn("_revalidate_output_parent(stderr)", runtime)
        self.assertIn("Claude output temporary cleanup failed", runtime)
        self.assertIn("Claude output cleanup or rollback remained incomplete", runtime)
        self.assertIn("Claude output path must not already exist", runtime)
        self.assertIn("Claude output parent must be a real directory", runtime)
        self.assertIn("Claude output parent must not traverse a symlink", runtime)

    def test_named_lane_guard_failure_classification_is_subcommand_specific(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            self.assertIn("blocked-safety", content)
            self.assertIn("run-claude", content)
            self.assertIn("inconclusive", content)
        self.assertIn(
            "Every bounded Git/materialization/preflight/cleanup error", skill
        )
        self.assertIn("Every bounded Git, output-limit, deadline", contracts)
        self.assertIn("Every `run-claude` supervision failure", contracts)
        self.assertIn(
            "Every bounded materialization, validation, or cleanup failure", canonical
        )
        self.assertIn("Every `run-claude` supervision failure", canonical)
        self.assertIn('args.command_name == "validate-worktree"', runtime)
        self.assertIn('"blocked-safety"', runtime)
        self.assertIn('"inconclusive"', runtime)

    def test_direct_claude_guard_has_finite_process_boundaries(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        entrypoint_path = SCRIPTS / "named_lane_guard"
        entrypoint = entrypoint_path.read_text(encoding="utf-8")
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            self.assertIn("run-claude", content)
            self.assertIn("1,800-second monotonic deadline", content)
            self.assertIn("worktree Git", content)
            self.assertIn("64 MiB", content)
            self.assertIn("128 MiB aggregate", content)
            self.assertIn("TERM/KILL/drain/reap", content)
            self.assertIn("direct", content)
            self.assertIn("inconclusive", content)
            self.assertIn("partial", content)
            self.assertIn("initial supervisor process group", content)
            self.assertIn("inherited stream", content)
            self.assertIn("setsid()", content)
            self.assertIn("not a process-tree sandbox", content)
        for non_guarantee in (
            "prepare",
            "review logic",
            "executable provenance",
            "authenticate",
            "general content/secrets",
        ):
            self.assertIn(non_guarantee, contracts)
        self.assertIn("direct child `argv[0]`", canonical)
        self.assertIn("direct argv/no shell", canonical)
        self.assertIn("Only complete structured terminal output", canonical)
        self.assertEqual(entrypoint_path.stat().st_mode & 0o111, 0)
        self.assertFalse(entrypoint.startswith("#!"))
        self.assertIn("named_lane_guard requires Python 3.10 or later", entrypoint)
        self.assertIn("sys.flags.isolated", entrypoint)
        self.assertIn("sys.flags.ignore_environment", entrypoint)
        self.assertIn("sys.flags.no_site", entrypoint)
        self.assertIn("sys.flags.no_user_site", entrypoint)
        self.assertIn("sys.flags.dont_write_bytecode", entrypoint)
        self.assertIn("invoked with -I -B -S", entrypoint)
        self.assertIn("_read_bound_source", entrypoint)
        self.assertIn("_load_bound_sources", entrypoint)
        self.assertIn("_load_default_entrypoint", entrypoint)
        self.assertIn("_select_entrypoint", entrypoint)
        self.assertIn('("review_runtime", "__init__.py", True)', entrypoint)
        self.assertIn('("review_runtime.common", "common.py", False)', entrypoint)
        self.assertIn(
            '("review_runtime.named_lane", "named_lane.py", False)', entrypoint
        )
        self.assertNotIn("sys.path.insert", entrypoint)
        self.assertNotIn("from review_runtime", entrypoint)
        self.assertLess(
            entrypoint.index("sys.flags.no_site"),
            entrypoint.index("main, _MAIN_ARGV = _select_entrypoint"),
        )
        self.assertIn("DEFAULT_TIMEOUT_SECONDS = 1_800.0", runtime)
        self.assertIn("DEFAULT_STREAM_LIMIT_BYTES = 64 * 1024 * 1024", runtime)
        self.assertIn("_read_control_prompt", runtime)
        self.assertIn("_structured_forwarded_signals", runtime)
        self.assertIn("_remaining_deadline_seconds", runtime)
        self.assertIn("withholds EOF", canonical)
        self.assertIn("withholds EOF", contracts)
        self.assertIn("structured `inconclusive` / `forwarded-signal`", canonical)
        self.assertIn("reason `forwarded-signal`", contracts)
        self.assertIn("run_bounded_capture", runtime)
        self.assertIn("whole-process-tree quiescence", canonical)

    def test_direct_claude_test_overrides_cannot_raise_production_caps(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SCRIPTS / "review_runtime/named_lane.py").read_text(encoding="utf-8")

        for content in (skill, contracts, canonical):
            self.assertIn("test-oriented", content.lower())
            self.assertIn("1,800", content)
            self.assertIn("64 MiB", content)
            self.assertIn("256 KiB", content)
            self.assertIn("Python", content)
        for anchor in (
            "DEFAULT_TIMEOUT_SECONDS = 1_800.0",
            "DEFAULT_STREAM_LIMIT_BYTES = 64 * 1024 * 1024",
            "DEFAULT_PROMPT_LIMIT_BYTES = 256 * 1024",
            "_validate_timeout_limit",
            "_validate_byte_limit",
            '"--timeout-seconds"',
            '"--stream-limit-bytes"',
            '"--prompt-limit-bytes"',
        ):
            self.assertIn(anchor, runtime)

    def test_named_lane_separates_artifact_outcome_and_presentation(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "raw findings-only terminal result",
            "Preserve the complete raw result",
            "`artifact_status`",
            "`review_outcome`",
            "`presentation`",
            "`canonical-clean`",
            "`extended-clean`",
            "`contradictory`",
            "`ambiguous`",
            "`nonconforming`",
            "outer ASCII whitespace",
            "quoted, inline, repeated, or non-final `No findings.`",
            "classify_review_result(raw_result, content_assessment=...)",
            "validator remains the sole authority for artifact acceptance",
            "logical lane and actual runtime/provider",
            "full frozen range and workspace identity",
            "Commands, tests, or residual risk may be added",
            "optional metadata",
            "must not be demanded from a reviewer whose raw output contract is findings-only",
        ):
            self.assertIn(anchor, contracts)
        for content in (skill, canonical):
            self.assertIn("artifact_status", content)
            self.assertIn("review_outcome", content)
            self.assertIn("presentation", content)
            self.assertIn("review_result.py", content)
            self.assertIn("never", content.lower())
        self.assertIn("validator returns it unchanged", canonical)
        self.assertIn("never substitutes for validator acceptance", canonical)
        self.assertIn("one concise non-actionable positive/coverage summary", canonical)
        self.assertIn("final nonempty logical line exactly `No findings.`", canonical)
        self.assertIn("final nonempty logical line must be exactly", templates)
        self.assertIn(
            "If there is any finding, do not output `No findings.` anywhere.", templates
        )
        self.assertNotIn("reply exactly: No findings.", templates)
        self.assertNotIn("exactly `No findings.` when clean", contracts)

        for content in (skill, contracts):
            self.assertIn("Rerun only", content)
            self.assertIn("range/head", content)
            self.assertIn("new head", content)
            self.assertIn("explicit", content)
            self.assertIn("decision point", content)

    def test_native_claude_selected_deny_policy_does_not_overclaim_host_read_isolation(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )

        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts, runtime):
            self.assertIn("not a global host-read whitelist", content)
            self.assertIn("global `denyWrite`", content)
            self.assertIn("critical-sensitive-root", content)
            self.assertIn("final merged", content)
        for content in (skill, contracts):
            self.assertIn("advertised capability surface", content)
        self.assertIn("Capability probes and the first `system/init` event", runtime)

        for anchor in (
            '"denyRead"',
            '"allowRead"',
            '"denyWrite": ["/"]',
            "critical sensitive roots",
            "not a global host-read whitelist",
            "advertised capability surface",
            "final merged sandbox",
        ):
            self.assertIn(anchor, canonical)

        self.assertIn("Sandboxed Bash can technically read", runtime)
        self.assertIn(
            "The prompt/model scope therefore explicitly forbids all outside-workspace reads",
            runtime,
        )
        self.assertIn(
            "Do not directly read any path outside this detached workspace",
            templates,
        )
        self.assertIn(
            "outside-workspace exclusion is a model/prompt scope rule",
            templates,
        )
        self.assertIn(
            "do not describe the selected-deny policy as re-opening only the current workspace",
            runtime,
        )
        self.assertNotIn("selected-deny policy re-opens only", runtime)
        self.assertNotIn("re-open only the current workspace", skill)
        for content in (skill, contracts):
            self.assertIn("requested configuration", content)
            self.assertNotIn(
                "native sandbox enforces global write denial",
                content.lower(),
            )
        self.assertIn("Persist sandbox controls as requested configuration", runtime)
        self.assertNotIn(
            "native sandbox enforces global write denial",
            runtime.lower(),
        )

    def test_claude_spill_scope_rule_and_observable_validator_gate_are_explicit(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        validator_source = (SCRIPTS / "validate_claude_stream.py").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts, canonical, templates):
            self.assertIn("persisted or spilled", content)
            self.assertIn("narrower bounded", content)
        for content in (skill, contracts, canonical):
            self.assertIn("`Read.file_path`", content)
            self.assertIn("`Grep.path`", content)
            self.assertIn("`Glob.path`", content)
            self.assertIn("`Glob.pattern`", content)
        for content in (contracts, canonical):
            self.assertIn("`persistedOutputPath`", content)
            self.assertIn("`Bash` command strings", content)
            self.assertIn("not complete host-read enforcement", content)

        self.assertIn(
            "A direct structured tool read of the spilled path adds deterministic blocked evidence",
            canonical,
        )
        self.assertIn(
            "if an outside-workspace tool read already occurred, the lane is blocked",
            templates,
        )
        self.assertIn(
            "intermediate.tool-path.outside-workspace",
            canonical,
        )
        self.assertIn(
            "intermediate.tool-path.scope-unverified",
            canonical,
        )
        for content in (skill, contracts, canonical, templates):
            self.assertIn("absolute", content)
            self.assertIn("`**/*.py`", content)
            self.assertIn("`./**/*.py`", content)
            self.assertIn("extglob", content)
            self.assertIn("ABA", content)
        for content in (skill, contracts, canonical):
            self.assertIn("validation start", content)
            self.assertIn("global", content)
            self.assertIn("inconclusive", content)
        for content in (skill, contracts, canonical):
            self.assertIn("`named-parent-private-preflight`", content)
            self.assertIn("`low-level-helper`", content)
        for anchor in (
            "STRUCTURED_TOOL_PATH_SCOPE_CONTRACT",
            "TRUST_SOURCE_LAUNCH_PROFILES",
            '"launch_profiles": ("named-direct",)',
            '"source": "assistant.tool_use.input"',
            '"path_field": "file_path"',
            '"path_field": "path"',
            '"path_if_present": "absolute"',
            '"path_if_present": "absolute_or_cwd_relative"',
            '"relative_path_base": "host_workspace_cwd"',
            '"home_shorthand": "scope_unverified"',
            '"pattern_field": "pattern"',
            '"pattern_contract": "bounded_safe_relative_glob"',
            '"leading_prefix_normalization": "./"',
            '"extglob": "scope_unverified"',
            '"dynamic_directory_containment": "bounded_overapprox_scan"',
            '"glob_scan_limits"',
            "MAX_STRUCTURED_GLOB_ALTERNATIVES = 64",
            "MAX_STRUCTURED_GLOB_SCAN_ENTRIES = 32_768",
            "MAX_STRUCTURED_GLOB_SCAN_STATES = 32_768",
            "MAX_STRUCTURED_GLOB_SCAN_DEPTH = 64",
            "STRUCTURED_GLOB_EXTGLOB_TOKENS",
            "_bounded_glob_directory_scope",
            "with os.scandir(resolved_current) as entries",
            "_open_bound_workspace(resolved_cwd)",
            '"user.tool_use_result.persistedOutputPath"',
            '"Bash.command"',
        ):
            self.assertIn(anchor, validator_source)
        self.assertNotIn("persistedOutputPath", validator_source.split("def ", 1)[1])

    def test_canonical_claude_auth_control_plane_is_not_helper_broker(self) -> None:
        agents = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        lane_contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "ordinary local Claude CLI login",
            "only authentication interface",
            "trusted control plane",
            "accepts no API key",
            "OAuth-token environment interface",
            "ordinary CLI-owned authentication and runtime state",
            "credential refresh and possible cache or tool-result artifacts",
            "not model-authorized review mutations",
            "does not use the low-level helper's credential broker",
            "blocked-authentication",
            "claude auth login",
            "`--no-session-persistence` disables resumable session persistence",
            "does not make the CLI process or real `HOME` immutable",
            "does not take or verify a complete real-`HOME` diff",
        ):
            self.assertIn(anchor, canonical)
        canonical_runtime = runtime[
            runtime.index("### Canonical Lane Applicability") : runtime.index(
                "### Native Selected-Deny Read Boundary"
            )
        ]
        canonical_runtime_normalized = " ".join(canonical_runtime.split())
        for anchor in (
            "only authentication interface",
            "ordinary local Claude CLI login",
            "accepts no API key",
            "OAuth-token environment interface",
            "blocked-authentication",
        ):
            self.assertIn(anchor, canonical_runtime_normalized)
        self.assertNotIn("explicitly authorized API key", canonical_runtime)
        self.assertIn("only API-key/OAuth-token credentials", canonical)
        self.assertIn(
            "organization policy forbids ordinary CLI control-plane writes", canonical
        )
        self.assertIn("The canonical lane does not use or", runtime)
        self.assertIn("helper's credential-lock catalog", runtime)
        self.assertIn(
            "The canonical lane does not enumerate or attest every CLI-owned `HOME` write",
            runtime,
        )
        self.assertIn("helper's credential-lock", runtime)
        self.assertIn("Do not apply its catalog, broker, carrier, lock", runtime)
        self.assertIn("do not apply to this direct real-`HOME` lane", skill)
        for content in (skill, lane_contracts, canonical, runtime):
            self.assertIn(
                "ordinary CLI-owned authentication and runtime state",
                content,
            )
            self.assertIn("credential refresh", content)
            self.assertIn("cache or tool-result artifacts", content)
            self.assertIn("not model-authorized", content)
            for overclaim in (
                "only planned host write",
                "only planned host-write exception",
                "does not authorize any other host write",
                "a narrow CLI control-plane exception",
            ):
                self.assertNotIn(overclaim, content)
        self.assertIn(
            "Apply **Compatible-Version Selection Preflight** and **Canonical Executable Provenance**",
            lane_contracts,
        )
        self.assertIn("recovery rules do not apply to this direct lane", lane_contracts)
        self.assertNotIn("authentication, credential-recovery", lane_contracts)
        if CI_PROFILE == "canonical":
            self.assertIn("real `HOME`", agents)
            self.assertIn("Those guarantees do not apply", agents)
        else:
            self.assertIn(
                "never count a supplied-diff helper as a named lane",
                agents,
            )
            self.assertIn("Named double adds actual Claude Code", agents)
        for retired_global_detail in (
            "Local-login writeback requires",
            "broker `W` generation",
            "primary `.oauth_refresh.lock`",
            "last generation and 1 MiB",
            "helper's credential-lock",
        ):
            self.assertNotIn(retired_global_detail, agents)

    def test_canonical_claude_provenance_rejects_npm_nvm_shims(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts, canonical):
            self.assertIn("npm/NVM", content)
            self.assertIn("shebang shims", content)
            self.assertIn("script", content)
            self.assertIn("interpreter wrapper", content)
            self.assertIn("trusted `PATH`", content)
            self.assertIn("does not establish", content)
        self.assertIn("user-writable npm/NVM directory", canonical)
        self.assertIn("does not establish publisher provenance", canonical)

    def test_canonical_claude_launch_uses_preflight_bound_verified_snapshot(
        self,
    ) -> None:
        canonical = (SKILL_ROOT / "references/canonical-claude-lane.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (SKILL_ROOT / "references/claude-runtime-trust.md").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        implementation = (SCRIPTS / "review_runtime/named_lane.py").read_text(
            encoding="utf-8"
        )

        for content in (skill, contracts, canonical, runtime_trust):
            for anchor in (
                "--preflight-result",
                "verified-snapshot",
                "`mtime`",
                "`ctime`",
                "`nlink`",
                "benign churn",
                "raw source path",
                "forwarded-signal-masked",
                "snapshot-cleanup",
                "`process_reason`",
                "`retained_path`",
                "`retained_locator`",
                "complete flushed",
                "receipt write/flush failure",
            ):
                with self.subTest(anchor=anchor):
                    self.assertIn(anchor, content)
        for anchor in (
            "## Canonical Executable Provenance",
            "fixed Anthropic release-signing key",
            "signed manifest",
            "guard-created verified snapshot",
            "opened source descriptor",
            "single-link mode-`0500` snapshot",
            "cannot alter the executed bytes",
            "without claiming the raw host path itself ran or requiring parent before/after raw-path checks",
            "`launch_binding`",
            "preflight SHA-256",
            "signed artifact size/SHA-256",
        ):
            self.assertIn(anchor, canonical)
        self.assertIn("Before invoking `validate-claude-stream`", skill)
        self.assertIn("Before stream validation", contracts)
        self.assertIn("Before invoking the stream validator", canonical)
        self.assertIn("Before stream validation", runtime_trust)
        for content in (skill, contracts, canonical, runtime_trust):
            self.assertIn("does not consume", content)
            self.assertNotIn("source descriptor open through process spawn", content)
            self.assertNotIn("snapshot descriptor open through process spawn", content)
        for content in (skill, contracts, canonical):
            for field in (
                "preflight_sha256",
                "resolved_path",
                "identity",
                "artifact_sha256",
                "artifact_size",
            ):
                with self.subTest(field=field):
                    self.assertIn(field, content)
        self.assertNotIn(
            "revalidate that exact resolved path immediately before and after launch",
            runtime_trust,
        )
        self.assertNotIn(
            "uses the revalidated host-installed executable path for the actual",
            canonical,
        )

        self.assertIn(
            'claude.add_argument("--preflight-result", required=True)',
            implementation,
        )
        self.assertIn("_read_claude_preflight_evidence", implementation)
        self.assertIn("_create_claude_launch_snapshot", implementation)
        self.assertIn("snapshot_command = (str(snapshot.path)", implementation)
        self.assertIn("snapshot_mask = block_forwarded_signals()", implementation)
        self.assertIn("class _ClaudeLaunchSnapshotCleanupError", implementation)
        self.assertIn('"reason": "snapshot-cleanup"', implementation)
        self.assertIn("_output_parent_path_names_bound_directory", implementation)
        self.assertIn('payload["retained_locator"]', implementation)
        self.assertIn("def _emit_claude_receipt", implementation)
        self.assertIn("_receipt_emitter=_emit_claude_receipt", implementation)
        snapshot_creation = implementation.split(
            "def _create_claude_launch_snapshot(", 1
        )[1].split("def _cleanup_claude_launch_snapshot(", 1)[0]
        self.assertEqual(
            snapshot_creation.count("_remaining_deadline_seconds("),
            2,
        )
        self.assertIn('"mode": "verified-snapshot"', implementation)
        self.assertIn('"preflight_sha256": binding.preflight_checksum', implementation)
        self.assertIn('"resolved_path": str(binding.source_path)', implementation)
        self.assertIn(
            '"identity": dict(_expected_executable_identity(binding))',
            implementation,
        )
        self.assertIn('"artifact_sha256": binding.artifact_checksum', implementation)
        self.assertIn('"artifact_size": binding.artifact_size', implementation)
        expected_identity = implementation.split(
            "def _expected_executable_identity(", 1
        )[1].split("def _write_all(", 1)[0]
        for field in ("device", "inode", "file_type", "mode", "uid", "gid", "size"):
            self.assertIn(f'"{field}"', expected_identity)
        for excluded in ("nlink", "mtime", "ctime"):
            self.assertNotIn(excluded, expected_identity)
        self.assertIn(
            "Follow **Compatible-Version Selection**, **Canonical Executable Provenance**",
            skill,
        )

    def test_all_superseded_auth_journals_are_historical_helper_only(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("public project journals are not packaged in private overlay")
        journal_names = (
            "2026-07-03-claude-local-login-b4e9d1.md",
            "2026-07-15-claude-cli-platform-capabilities-7c1501.md",
            "2026-07-16-claude-oauth-per-attempt-freshness-662f2c.md",
            "2026-07-17-claude-auth-carriers-c17a11.md",
        )

        for journal_name in journal_names:
            journal = (
                REPO_ROOT / "docs/project_journal/2026/07" / journal_name
            ).read_text(encoding="utf-8")
            normalized = " ".join(
                line.removeprefix("> ").strip() for line in journal.splitlines()
            )
            with self.subTest(journal=journal_name):
                for anchor in (
                    "Historical helper record",
                    "low-level `isolated_review` helper",
                    "do not define named single, double, or triple review",
                    "do not apply to the canonical direct Claude lane",
                ):
                    self.assertIn(anchor, normalized)
                self.assertRegex(journal, r"superseded_by: 202607(?:17|20)-")
                self.assertIn("## Historical Helper State", journal)
                self.assertNotIn("## Current State", journal)

    def test_current_policy_journals_use_the_current_claude_contract(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("public project journals are not packaged in private overlay")

        journal_root = REPO_ROOT / "docs/project_journal/2026/07"
        historical_marker = "\n## Historical Superseded Implementation Evidence\n"
        required_by_journal = {
            "2026-07-17-secret-reduction-gate-7f1703.md": (
                "actual Claude Code",
                "review_contract: supplied-diff-private-git",
                "helper-owned detached workspace backed by private minimal Git",
                "publisher-verified strict stable Claude Code `>=2.1.211,<3.0.0`",
                "signed per-version manifest",
                "`--version` and `--help`",
                "same private digest-verified executable snapshot",
            ),
            "2026-07-19-real-home-read-only-claude-c63d11.md": (
                "named direct Claude lane",
                "real `HOME`",
                "review_contract: supplied-diff-private-git",
                "`--include-source-wip`",
                "accepts only ordinary local login",
                "low-level helper selects authentication with "
                "`ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local login",
                "broker/carrier/catalog/full refresh transaction",
                "publisher-verified strict stable Claude Code `>=2.1.211,<3.0.0`",
                "claude_version_policy.py",
                "`legacy-base`",
                "`extended-2x`",
            ),
            "2026-07-20-review-policy-migration-7f2001.md": (
                "directly launched actual Claude Code",
                "review_contract: supplied-diff-private-git",
                "helper-owned detached workspace backed by private minimal Git",
                "broker, staged carrier",
                "full refresh transaction",
                "named direct real-`HOME` lane does not inherit",
                "publisher-verified strict stable Claude Code `>=2.1.211,<3.0.0`",
                "same private digest-verified executable snapshot",
            ),
            "2026-07-19-claude-refresh-transaction-crt001.md": (
                "explicit API-key and OAuth-token modes independent of local-login carrier coordination",
                "one outer refresh-lock lease",
                "broker execution",
                "Linux/WSL2 credential staging",
                "final drain",
                "private carrier",
                "descriptor-bound",
            ),
            "2026-07-22-claude-compatible-version-range-7f2201.md": (
                "`>=2.1.211,<3.0.0`",
                "one production source of truth",
                "claude_version_policy.py",
                "audited per-version stream-schema baseline",
                "not a global eligibility pin",
                "`legacy-base`",
                "`extended-2x`",
                "strict-version-and-launch-profiles",
            ),
        }
        forbidden_by_journal = {
            "2026-07-17-secret-reduction-gate-7f1703.md": (
                "supplied-diff-no-git",
                "supplied-diff/no-git",
                "`.git`-free",
                ".git-free",
            ),
            "2026-07-19-real-home-read-only-claude-c63d11.md": (
                "no separate mandatory help",
                "no separate mandatory `--help`",
            ),
            "2026-07-20-review-policy-migration-7f2001.md": (
                "no separate mandatory help",
                "no separate mandatory `--help`",
            ),
            "2026-07-22-claude-compatible-version-range-7f2201.md": (
                "requires exactly Claude Code `2.1.212`",
                "require exactly Claude Code `2.1.212`",
                "exact-version-mismatch",
                "exact-version-unavailable",
                "adapts only the init version constant",
            ),
        }

        for journal_name, required_anchors in required_by_journal.items():
            journal = (journal_root / journal_name).read_text(encoding="utf-8")
            active, marker, historical = journal.partition(historical_marker)
            with self.subTest(journal=journal_name):
                for anchor in required_anchors:
                    self.assertIn(anchor, active)
                for forbidden in forbidden_by_journal.get(journal_name, ()):
                    self.assertNotIn(forbidden, active)
                    if forbidden in journal:
                        self.assertEqual(marker, historical_marker)
                        self.assertIn(forbidden, historical)

    def test_migration_journal_requires_zero_inherited_turns_for_single(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest("public project journals are not packaged in private overlay")
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-20-review-policy-migration-7f2001.md"
        ).read_text(encoding="utf-8")

        self.assertIn("one dedicated fresh-context Codex reviewer", journal)
        self.assertIn("zero inherited turns", journal)
        self.assertNotIn("fresh or otherwise clear-context", journal)

    def test_readme_separates_canonical_claude_from_helper_only_details(self) -> None:
        if CI_PROFILE != "canonical":
            self.skipTest(
                "canonical public README section layout is not part of private profile"
            )
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        boundary = readme.index("## Low-Level `isolated_review` Helper Only")

        self.assertLess(readme.index("accepted real-`HOME`"), boundary)
        self.assertLess(readme.index("`>=2.1.211,<3.0.0`"), boundary)
        self.assertLess(readme.index("signed per-version manifest"), boundary)
        for helper_detail in (
            "review_contract: supplied-diff-private-git",
            "helper-owned detached worktree backed by private minimal Git",
            "`ANTHROPIC_API_KEY` > `CLAUDE_CODE_OAUTH_TOKEN` > local login",
            "explicit source is opaque-forwarded",
            "private, checksum-keyed executable snapshot",
            "dedicated writable `/auth` carrier root",
            "Low-level helper Claude authentication",
            "Low-level helper local-login refresh writeback",
            "For the low-level helper, missing, malformed, unsafe",
        ):
            self.assertGreater(readme.index(helper_detail), boundary)
        self.assertIn(
            "not requirements or guarantees of the canonical direct Claude lane",
            readme,
        )
        self.assertIn("cannot satisfy named double or triple review", readme)

    def test_core_active_policy_has_no_retired_codex_pr_gate_names(self) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        active_policy = [
            _repository_agents_path(REPO_ROOT, CI_PROFILE),
            policy_scope_root / "agents/reviewer.toml",
            policy_scope_root / "skills/change-delivery-workflow/SKILL.md",
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "agents/openai.yaml",
            SKILL_ROOT / "references/canonical-claude-lane.md",
            SKILL_ROOT / "references/egress-consent.md",
            SKILL_ROOT / "references/github-codex-evidence-authority.md",
            SKILL_ROOT / "references/github-pr-probes.md",
            SKILL_ROOT / "references/pr-readiness.md",
            SKILL_ROOT / "references/review-lane-contracts.md",
            SKILL_ROOT / "references/review-prompt-templates.md",
        ]
        if CI_PROFILE == "canonical":
            active_policy.append(REPO_ROOT / "README.md")
            compatibility = (
                REPO_ROOT / ".github/workflows/codex-review-gate.yml"
            ).read_text(encoding="utf-8")
            self.assertIn("Compatibility Status", compatibility)
            self.assertNotIn("\n      - uses:", compatibility)
        retired = (
            "independent-codex-pr-review",
            "offline-frozen-diff-review",
        )

        for candidate in active_policy:
            content = candidate.read_text(encoding="utf-8")
            for name in retired:
                with self.subTest(candidate=candidate, retired=name):
                    self.assertNotIn(name, content)

    def test_active_named_lane_policy_has_no_unimplemented_overstrict_contracts(
        self,
    ) -> None:
        policy_scope_root = _repository_policy_scope_root(REPO_ROOT, CI_PROFILE)
        active_policy = [
            _repository_agents_path(REPO_ROOT, CI_PROFILE),
            policy_scope_root / "agents/reviewer.toml",
            policy_scope_root / "skills/change-delivery-workflow/SKILL.md",
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "agents/openai.yaml",
            SKILL_ROOT / "references/canonical-claude-lane.md",
            SKILL_ROOT / "references/egress-consent.md",
            SKILL_ROOT / "references/github-codex-evidence-authority.md",
            SKILL_ROOT / "references/pr-readiness.md",
            SKILL_ROOT / "references/review-lane-contracts.md",
            SKILL_ROOT / "references/review-prompt-templates.md",
        ]
        if CI_PROFILE == "canonical":
            active_policy.append(REPO_ROOT / "README.md")
        retired_overstrict_terms = (
            "raw-object-equivalent",
            "range-scoped endpoint object closure",
            "only executable Git surface",
            "immutable instruction snapshot",
            "provider-neutral sensitive-content preflight",
        )

        for candidate in active_policy:
            content = candidate.read_text(encoding="utf-8")
            for term in retired_overstrict_terms:
                with self.subTest(candidate=candidate, term=term):
                    self.assertNotIn(term, content)

    def test_foreground_helper_does_not_claim_a_machine_labeled_envelope(self) -> None:
        cli_source = (SKILL_ROOT / "scripts/review_runtime/cli.py").read_text(
            encoding="utf-8"
        )
        completed = subprocess.run(
            (str(SCRIPTS / "isolated_review"), "--help"),
            cwd=REPO_ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        help_text = " ".join(completed.stdout.split())

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn(
            "Results are diagnostic and machine-labeled",
            help_text,
        )
        self.assertIn(
            "the foreground command prints only the raw helper artifact",
            help_text,
        )
        self.assertIn(
            "The foreground compatibility command likewise prints only the raw helper artifact",
            helper_contract,
        )
        self.assertIn(
            "Automation that needs machine-readable contract metadata must use `stateful status`",
            helper_contract,
        )
        self.assertNotIn("render_success_envelope", cli_source)

    def test_installed_bundle_entrypoints_do_not_create_bytecode(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="review-installed-no-bytecode-"
        ) as temporary:
            copied_skill = pathlib.Path(temporary) / "review-orchestration-playbook"
            shutil.copytree(
                SKILL_ROOT,
                copied_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            copied_scripts = copied_skill / "scripts"
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)
            entrypoints = {
                copied_scripts / "isolated_review": 0,
                copied_scripts / "named_claude_preflight": 2,
                copied_scripts / "validate_claude_stream.py": 3,
                copied_scripts
                / "independent_codex_pr_review"
                / "independent-codex-pr-review": 0,
            }
            discovered_entrypoints = {
                path
                for path in copied_scripts.rglob("*")
                if path.is_file() and _has_python_shebang(path)
            }
            self.assertEqual(discovered_entrypoints, set(entrypoints))

            for entrypoint, expected_returncode in entrypoints.items():
                with self.subTest(entrypoint=entrypoint.name):
                    completed = subprocess.run(
                        (sys.executable, str(entrypoint), "--help"),
                        cwd=copied_skill,
                        env=environment,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30,
                    )
                    requires_python_313 = (
                        entrypoint.name == "independent-codex-pr-review"
                    )
                    if requires_python_313 and sys.version_info < (3, 13):
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn(
                            "Python 3.13 is required; running",
                            completed.stderr,
                        )
                    else:
                        self.assertEqual(
                            completed.returncode,
                            expected_returncode,
                            completed.stderr,
                        )
                    bytecode = sorted(
                        path.relative_to(copied_skill)
                        for path in copied_skill.rglob("*")
                        if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
                    )
                    self.assertEqual(bytecode, [])

            import_probe = (
                "import sys;"
                f"sys.path.insert(0, {str(copied_scripts)!r});"
                "import review_runtime;"
                "sys.path.insert(0, "
                f"{str(copied_scripts / 'independent_codex_pr_review')!r});"
                "import review_supervisor"
            )
            imported = subprocess.run(
                (sys.executable, "-B", "-c", import_probe),
                cwd=copied_skill,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)

            bytecode = sorted(
                path.relative_to(copied_skill)
                for path in copied_skill.rglob("*")
                if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
            )
            self.assertEqual(bytecode, [])

    @unittest.skipIf(
        sys.version_info < (3, 13),
        "the independent supervisor requires Python 3.13",
    )
    def test_installed_supervisor_preflight_keeps_release_tree_immutable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="review-installed-preflight-immutable-"
        ) as temporary:
            root = pathlib.Path(temporary)
            release_skill = (
                root
                / "releases"
                / ("b" * 40)
                / "personal_codex"
                / "skills"
                / "review-orchestration-playbook"
            )
            shutil.copytree(
                SKILL_ROOT,
                release_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            stable_skill = root / "stable/review-orchestration-playbook"
            stable_skill.parent.mkdir(mode=0o700)
            stable_skill.symlink_to(release_skill, target_is_directory=True)
            tool_root = stable_skill / "scripts" / "independent_codex_pr_review"
            entrypoint = tool_root / "independent-codex-pr-review"
            account_home = root / "account-home"
            account_home.mkdir(mode=0o700)
            repository = root / "repository"
            repository.mkdir(mode=0o700)

            def release_snapshot() -> dict[str, bytes | None]:
                return {
                    path.relative_to(release_skill).as_posix(): (
                        path.read_bytes() if path.is_file() else None
                    )
                    for path in (release_skill, *sorted(release_skill.rglob("*")))
                }

            before = release_snapshot()
            wrapper = root / "run-installed-preflight.py"
            wrapper.write_text(
                "\n".join(
                    (
                        "import os",
                        "import pwd",
                        "import runpy",
                        "import sys",
                        "",
                        "account = type(",
                        "    'Account',",
                        "    (),",
                        "    {'pw_dir': os.environ['TEST_ACCOUNT_HOME']},",
                        ")()",
                        "pwd.getpwuid = lambda _uid: account",
                        "entrypoint = os.environ['TEST_ENTRYPOINT']",
                        "sys.path.insert(0, os.path.dirname(entrypoint))",
                        "sys.argv = [entrypoint, *sys.argv[1:]]",
                        "runpy.run_path(entrypoint, run_name='__main__')",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)
            environment.update(
                {
                    "TEST_ACCOUNT_HOME": str(account_home),
                    "TEST_ENTRYPOINT": str(entrypoint),
                }
            )
            completed = subprocess.run(
                (
                    sys.executable,
                    "-B",
                    str(wrapper),
                    "preflight",
                    "--helper-state",
                    str(root / "missing-helper-state"),
                    "--repo",
                    str(repository),
                    "--base",
                    "1" * 40,
                    "--head",
                    "2" * 40,
                    "--pr-url",
                    "https://github.com/example/example/pull/1",
                ),
                cwd=tool_root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 2, completed.stderr)
            payload = json.loads(completed.stdout)
            self.assertNotEqual(payload.get("status"), "ready")

            state_root = (
                account_home
                / ".codex"
                / "review-runtime"
                / "independent-codex-pr-review"
            )
            self.assertTrue((state_root / "retention").is_dir())
            self.assertTrue((state_root / "checkouts").is_dir())
            self.assertFalse((release_skill / "runtime").exists())
            self.assertEqual(release_snapshot(), before)

    def test_documented_validation_does_not_create_bundle_bytecode(self) -> None:
        syntax_probe = (
            "import pathlib, sys; "
            '[compile(pathlib.Path(path).read_bytes(), path, "exec") '
            "for path in sys.argv[1:]]"
        )
        if CI_PROFILE == "canonical":
            readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
            self.assertIn(f"python3 -B -c '{syntax_probe}'", readme)
            self.assertIn(
                "python3 -B -m unittest discover "
                "-s skills/review-orchestration-playbook/tests",
                readme,
            )

        with tempfile.TemporaryDirectory(
            prefix="review-documented-validation-"
        ) as temporary:
            copied_skill = pathlib.Path(temporary) / "review-orchestration-playbook"
            shutil.copytree(
                SKILL_ROOT,
                copied_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            copied_scripts = copied_skill / "scripts"
            syntax_sources = [
                copied_scripts / "isolated_review",
                copied_scripts / "named_lane_guard",
                *sorted((copied_scripts / "review_runtime").glob("*.py")),
            ]
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)

            syntax_check = subprocess.run(
                (
                    sys.executable,
                    "-B",
                    "-c",
                    syntax_probe,
                    *(str(path) for path in syntax_sources),
                ),
                cwd=copied_skill,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(syntax_check.returncode, 0, syntax_check.stderr)

            tests = subprocess.run(
                (
                    sys.executable,
                    "-B",
                    "-m",
                    "unittest",
                    "test_named_lane.NamedLaneGuardTest."
                    "test_entrypoint_does_not_write_import_bytecode",
                ),
                cwd=copied_skill / "tests",
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
            self.assertEqual(tests.returncode, 0, tests.stderr)

            bytecode = sorted(
                path.relative_to(copied_skill)
                for path in copied_skill.rglob("*")
                if path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
            )
            self.assertEqual(bytecode, [])

    def test_bare_direct_package_import_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="review-installed-bare-import-"
        ) as temporary:
            copied_skill = pathlib.Path(temporary) / "review-orchestration-playbook"
            shutil.copytree(
                SKILL_ROOT,
                copied_skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            copied_scripts = copied_skill / "scripts"
            environment = os.environ.copy()
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            environment.pop("PYTHONPYCACHEPREFIX", None)
            environment.pop("PYTHONPATH", None)
            packages = {
                "review_runtime": copied_scripts,
                "review_supervisor": (copied_scripts / "independent_codex_pr_review"),
            }

            for package_name, import_root in packages.items():
                with self.subTest(package=package_name):
                    import_probe = (
                        "import sys;"
                        f"sys.path.insert(0, {str(import_root)!r});"
                        f"import {package_name}"
                    )
                    completed = subprocess.run(
                        (sys.executable, "-c", import_probe),
                        cwd=copied_skill,
                        env=environment,
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=30,
                    )
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertIn(
                        f"{package_name} requires bytecode to be disabled before import",
                        completed.stderr,
                    )

            bytecode = sorted(
                path.relative_to(copied_skill) for path in copied_skill.rglob("*.pyc")
            )
            self.assertEqual(len(bytecode), 2)
            self.assertTrue(
                all(path.name.startswith("__init__.") for path in bytecode),
                bytecode,
            )
            self.assertEqual(
                {path.parent.parent.name for path in bytecode},
                {"review_runtime", "review_supervisor"},
            )

    def test_installed_bundle_python_child_launchers_pass_no_bytecode(self) -> None:
        launch_vectors: list[tuple[pathlib.Path, int, str]] = []
        production_sources = [
            path
            for path in SCRIPTS.rglob("*")
            if path.is_file()
            and "tests" not in path.relative_to(SCRIPTS).parts
            and (path.suffix == ".py" or _has_python_shebang(path))
        ]
        for source_path in sorted(production_sources):
            source = source_path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(source_path))
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)) or len(node.elts) < 2:
                    continue
                first = ast.unparse(node.elts[0])
                if "sys.executable" not in first:
                    continue
                launch_vectors.append((source_path, node.lineno, first))
                leading_flags: list[str] = []
                for item in node.elts[1:]:
                    if not (
                        isinstance(item, ast.Constant)
                        and isinstance(item.value, str)
                        and item.value.startswith("-")
                    ):
                        break
                    leading_flags.append(item.value)
                self.assertIn(
                    "-B",
                    leading_flags,
                    f"{source_path}:{node.lineno} must pass -B",
                )
        self.assertGreaterEqual(len(launch_vectors), 9)

    def test_review_prompts_do_not_use_unbounded_only_matching_samples(self) -> None:
        forbidden = "rg -o --max-count 80"
        candidates = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "scripts/review_runtime/prompt.py",
        ]
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

    def test_named_review_consent_does_not_authorize_copilot(self) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "These requests do not authorize GitHub Copilot",
            consent,
        )
        self.assertIn(
            "GitHub Copilot requires a separate explicit request and consent",
            consent,
        )
        self.assertIn(
            "does not expand the named request to another provider",
            consent,
        )
        self.assertEqual(
            providers.COPILOT_EGRESS_CONSENTS,
            ("explicit-claude-with-copilot-fallback",),
        )
        self.assertNotIn("double-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertNotIn("triple-review", providers.CLAUDE_EGRESS_CONSENTS)
        self.assertNotIn("has no usable local/API authentication", consent)

    def test_named_review_egress_is_provider_specific_without_substitutes(
        self,
    ) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("Single authorizes OpenAI Codex", skill)
        self.assertIn("Double additionally authorizes Anthropic Claude Code", skill)
        self.assertIn(
            "Triple additionally authorizes, when supported, current-head GitHub Codex",
            skill,
        )
        self.assertIn("No named shape authorizes a substitute external reviewer", skill)

    def test_retained_refresh_locks_never_authorize_lexical_paths(self) -> None:
        required = (
            "Intentionally retained shared refresh-lock directories never "
            "authorize a lexical recovery or cleanup pathname; report only "
            "descriptor-bound residue."
        )
        candidates = (
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/helper-contract.md",
            SKILL_ROOT / "references/claude-runtime-trust.md",
        )
        forbidden = (
            "Report exact helper-owned lock paths only when",
            "paths only after a quiesced descriptor/no-follow identity proof",
            "Exact helper-owned paths are authoritative only after",
            "authoritative path or descriptor-bound recovery evidence",
            "Path-owned anchors may report exact recovery paths",
        )
        for candidate in candidates:
            content = candidate.read_text(encoding="utf-8")
            normalized = " ".join(content.split())
            self.assertIn(required, normalized, str(candidate))
            for phrase in forbidden:
                self.assertNotIn(phrase, normalized, str(candidate))

    def test_selected_pr_requires_exact_merge_base_and_head_range(self) -> None:
        agents_policy = _repository_agents_path(REPO_ROOT, CI_PROFILE).read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )
        templates = (SKILL_ROOT / "references/review-prompt-templates.md").read_text(
            encoding="utf-8"
        )
        policy_documents = {
            "repository policy": agents_policy,
            "skill": skill,
            "PR readiness": readiness,
            "lane contracts": contracts,
            "prompt templates": templates,
        }
        if CI_PROFILE == "canonical":
            policy_documents["README"] = (REPO_ROOT / "README.md").read_text(
                encoding="utf-8"
            )

        exact_range = "`base_sha == pr_merge_base` and `head_sha == pr_head_oid`"
        for name, content in policy_documents.items():
            with self.subTest(policy_document=name):
                self.assertIn("pr-lifecycle-unverified", content)
                self.assertIn("selected-pr-closed", content)
                self.assertIn("already-merged", content)
                self.assertIn("baseRefName", content)
                self.assertIn("baseRefOid", content)
                self.assertIn("headRefOid", content)
                self.assertIn("git merge-base --all", content)
                self.assertIn(exact_range, content)
                self.assertIn("same-head/different-base", content)
                self.assertIn("`blocked-input` (`scope-mismatch`)", content)
                self.assertIn("do not silently rewrite", content)
                self.assertIn("whole-PR coverage", content)
                self.assertIn("point-in-time snapshots", content.lower())

        self.assertIn("base_sha:.base.sha", probes)
        self.assertIn(
            "--jq '{number,url:.html_url,state,merged,merged_at,baseRefName:.base.ref,baseRefOid:.base.sha,headRefOid:.head.sha}'",
            probes,
        )
        self.assertIn('state == "open"', probes)
        self.assertIn("merged == false", probes)
        self.assertIn("merged_at == null", probes)
        for content in (readiness, probes, contracts):
            self.assertIn("`COMMENTED`, `APPROVED`, or `CHANGES_REQUESTED`", content)
            self.assertIn("`DISMISSED`", content)
            self.assertIn("triple-inconclusive", content)

        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        self.assertIn("state=open, merged=false, and merged_at=null", interface)
        self.assertIn("pr-lifecycle-unverified", interface)
        self.assertIn("selected-pr-closed", interface)
        self.assertIn("point-in-time snapshots", interface)
        self.assertNotIn("non-PENDING", interface)
        self.assertIn("gh api --hostname <host> --method GET", probes)
        self.assertNotIn("gh pr view <number> --repo <owner>/<repo>", probes)
        self.assertIn("exactly one full merge-base result", probes)
        self.assertIn("head_sha == pr_head_oid", probes)
        self.assertIn("base_sha != pr_merge_base", probes)
        self.assertIn("GIT_NO_LAZY_FETCH=1", probes)
        self.assertIn("GIT_TERMINAL_PROMPT=0", probes)
        self.assertIn("Zero/multiple merge bases", readiness)
        self.assertIn("Missing/ambiguous metadata, objects", skill)
        self.assertIn("point-in-time snapshots", probes.lower())
        self.assertIn("do not prove", probes.lower())

        preflight_anchor = "independently query and record lifecycle"
        run_lanes_anchor = "Run the requested local lanes"
        read_state_anchor = "Read required CI/check state"
        post_request_anchor = (
            "If no same-scope request exists, producer policy permits the parent "
            "to post one exact `@codex review` comment"
        )
        for later_anchor in (run_lanes_anchor, read_state_anchor, post_request_anchor):
            self.assertLess(
                readiness.index(preflight_anchor), readiness.index(later_anchor)
            )

        for content in (agents_policy, skill, readiness, contracts, probes, templates):
            self.assertIn(
                "explicit-range-only standalone single/double with no selected pr",
                content.lower(),
            )

    def test_early_github_request_does_not_poison_provider_evidence(self) -> None:
        documents = {
            "skill": SKILL_ROOT / "SKILL.md",
            "PR readiness": SKILL_ROOT / "references/pr-readiness.md",
            "lane contracts": SKILL_ROOT / "references/review-lane-contracts.md",
            "GitHub probes": SKILL_ROOT / "references/github-pr-probes.md",
            "prompt templates": SKILL_ROOT / "references/review-prompt-templates.md",
            "skill interface": SKILL_ROOT / "agents/openai.yaml",
        }
        if CI_PROFILE == "canonical":
            documents["README"] = REPO_ROOT / "README.md"
        for name, path in documents.items():
            content = " ".join(path.read_text(encoding="utf-8").split()).lower()
            with self.subTest(policy_document=name):
                self.assertIn("github-codex-evidence-authority.md", content)
                self.assertNotIn("later local-lane completion does not cure", content)
                self.assertNotIn("terminal payload cannot count", content)

        authority = (
            SKILL_ROOT / "references/github-codex-evidence-authority.md"
        ).read_text(encoding="utf-8")
        normalized = " ".join(authority.split()).lower()
        self.assertIn("early-request-observed", normalized)
        self.assertIn("warning-only", normalized)
        self.assertIn("outcome-neutral", normalized)
        self.assertIn(
            "a producer-side request policy violation does not erase otherwise "
            "complete provider-authored result evidence",
            normalized,
        )
        self.assertIn(
            "do not discard a later independently trustworthy provider result "
            "solely because of that producer-side sequencing defect",
            normalized,
        )
        self.assertIn("latest trustworthy terminal artifact", normalized)


if __name__ == "__main__":
    unittest.main()
