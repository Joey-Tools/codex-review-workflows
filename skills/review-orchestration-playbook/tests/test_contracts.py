from __future__ import annotations

import ast
import hashlib
import inspect
import json
import math
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

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
        expected_cache_guards = {"canonical": 3, "private": 5}
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
      - readonly_install_supervisor_tests
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
          BROKER_REPRODUCIBILITY_RESULT: ${{ needs.broker_reproducibility.result }}
          INDEPENDENT_SUPERVISOR_RESULT: ${{ needs.independent_supervisor_tests.result }}
          READONLY_INSTALL_SUPERVISOR_RESULT: ${{ needs.readonly_install_supervisor_tests.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
          test "$BROKER_REPRODUCIBILITY_RESULT" = "success"
          test "$INDEPENDENT_SUPERVISOR_RESULT" = "success"
          test "$READONLY_INSTALL_SUPERVISOR_RESULT" = "success"
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
      - readonly_install_supervisor_tests
    runs-on: ubuntu-latest
    steps:
      - name: Require every platform test to pass
        env:
          PLATFORM_TESTS_RESULT: ${{ needs.platform_tests.result }}
          PYTHON_39_RESULT: ${{ needs.python-39-compatibility.result }}
          PLATFORM_SAFETY_RESULT: ${{ needs.platform-safety.result }}
          BROKER_REPRODUCIBILITY_RESULT: ${{ needs.broker_reproducibility.result }}
          INDEPENDENT_SUPERVISOR_RESULT: ${{ needs.independent_supervisor_tests.result }}
          READONLY_INSTALL_SUPERVISOR_RESULT: ${{ needs.readonly_install_supervisor_tests.result }}
        run: |
          test "$PLATFORM_TESTS_RESULT" = "success"
          test "$PYTHON_39_RESULT" = "success"
          test "$PLATFORM_SAFETY_RESULT" = "success"
          test "$BROKER_REPRODUCIBILITY_RESULT" = "success"
          test "$INDEPENDENT_SUPERVISOR_RESULT" = "success"
          test "$READONLY_INSTALL_SUPERVISOR_RESULT" = "success"
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
        self.assertIn(
            f"passed {expected_count}/{expected_count}",
            journal,
        )
        self.assertIn(
            f"reviewed {expected_count}-test selected identity",
            journal,
        )
        self.assertIn(f"`{expected_sha256}`", journal)

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
        self.assertIn(
            "digest does not match the reviewed pin "
            "(expected=$expected actual=$actual)",
            script,
        )
        self.assertIn("verified %s sha256=%s", script)
        self.assertIn("select_hosted_codesign_sha256", script)
        self.assertIn('EXPECTED_HOSTED_OS_VERSION="26.5.2"', script)
        self.assertIn('EXPECTED_HOSTED_OS_BUILD="25F84"', script)
        self.assertIn('EXPECTED_HOSTED_LEGACY_OS_VERSION="26.4"', script)
        self.assertIn('EXPECTED_HOSTED_LEGACY_OS_BUILD="25E246"', script)
        self.assertIn(
            "hosted runner OS version/build is not reviewed",
            script,
        )
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

    def test_hosted_codesign_pin_journal_records_both_runner_generations(
        self,
    ) -> None:
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-30-hosted-broker-codesign-pin-hbp001.md"
        ).read_text(encoding="utf-8")
        for evidence in (
            "macOS 26.4 build `25E246`",
            "06eacc36d43376972d3bca0a2137ea4efd6d0fe27de8a7af0e6b11d599e8f337",
            "macOS 26.5.2 build `25F84`",
            "214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7",
            "90814780194",
            "8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16",
        ):
            self.assertIn(evidence, journal)

    def test_readonly_supervisor_journal_is_recovery_pointer(self) -> None:
        project_state = (REPO_ROOT / "docs/PROJECT_STATE.md").read_text(
            encoding="utf-8"
        )
        journal = (
            REPO_ROOT
            / "docs/project_journal/2026/07/"
            / "2026-07-30-readonly-supervisor-scratch-rss001.md"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "Latest workstream: "
            "`docs/project_journal/2026/07/"
            "2026-07-30-readonly-supervisor-scratch-rss001.md`",
            project_state,
        )
        for evidence in (
            "read-only installed releases",
            "untrusted `01777` ancestors",
            "ordinary deterministic suite passed 619/619",
            '"release_tree_immutable":true',
            '"runtime_residue":[]',
        ):
            self.assertIn(evidence, journal)

    def test_independent_supervisor_ci_separates_hosted_and_live_gates(self) -> None:
        live_runner = (
            SCRIPTS
            / "independent_codex_pr_review/tests/run_required_no_child_profile.py"
        ).read_text(encoding="utf-8")
        deterministic_runner = (
            SCRIPTS / "independent_codex_pr_review/tests/"
            "run_required_deterministic_supervisor.py"
        ).read_text(encoding="utf-8")
        readonly_install_runner = (
            SCRIPTS / "independent_codex_pr_review/tests/"
            "run_readonly_install_deterministic_supervisor.py"
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
        self.assertIn("EXPECTED_TEST_COUNT = 644", deterministic_runner)
        self.assertIn("EXPECTED_TEST_ID_SHA256 =", deterministic_runner)
        self.assertIn("selected_identity_sha256 !=", deterministic_runner)
        self.assertIn("excluded_keys != REQUIRED_TEST_KEYS", deterministic_runner)
        self.assertIn("if duplicate_keys:", deterministic_runner)
        self.assertIn("expected_discovered_count", deterministic_runner)
        self.assertIn("_test_key", deterministic_runner)
        for contract in (
            'READONLY_INSTALL_PARENT = pathlib.Path("/private/tmp")',
            "CODEX_REVIEW_TEST_RUNTIME_PARENT",
            "class TreeEntrySnapshot:",
            "device=metadata.st_dev",
            "inode=metadata.st_ino",
            'flags=getattr(metadata, "st_flags", 0)',
            "link_count=link_count",
            "metadata.st_nlink != 1",
            "xattrs=_xattr_snapshot(path)",
            "acl_entries=_acl_entries(path)",
            "_tree_property_unchanged(before, after)",
            "_set_tree_read_only(installed_root)",
            "run_bounded(",
            "CHILD_STDOUT_LIMIT_BYTES",
            "CHILD_STDERR_LIMIT_BYTES",
            "ChildProcessClosureUnproven",
            '"child_process_closure": child_process_closure',
            '"primary_failure": (',
            '"primary_status": primary_status',
            '"release_tree_immutable": release_tree_immutable',
            '"release_tree_property": "object-identity-content-access-policy"',
            '"cleanup_status": "incomplete" if cleanup_failures else "complete"',
            '"retained_paths": retained_paths',
            "return 1 if primary_failed or cleanup_failures else 0",
            '"tests.run_required_deterministic_supervisor"',
        ):
            self.assertIn(contract, readonly_install_runner)
        for excluded_signal in (
            "link_count=metadata.st_nlink",
            "size=metadata.st_size",
            "mtime_ns=metadata.st_mtime_ns",
            "ctime_ns=metadata.st_ctime_ns",
        ):
            self.assertNotIn(excluded_signal, readonly_install_runner)
        self.assertNotIn("ignore_errors=True", readonly_install_runner)
        self.assertLess(
            readonly_install_runner.index("cleanup_failures = tuple("),
            readonly_install_runner.index("print(json.dumps(summary"),
        )
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
            "_select_hosted_runtime_profile(observed_runtime)",
            "_matches_hosted_fail_closed_observations(evidence)",
            "blockers == expected_blockers",
            "len(blockers) == len(evidence.blockers)",
            '"reviewed_fail_closed_signature": signature_matches',
            '"runtime_profile": runtime_profile',
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
        for hosted_profile in (
            "github-macos-26-arm64-26.4-25E246",
            "github-macos-26-arm64-26.5.2-25F84",
        ):
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
            readonly_start = workflow.index(
                "\n  readonly_install_supervisor_tests:",
                start,
            )
            end = workflow.index(f"\n  {next_job}:", readonly_start)
            supervisor_job = workflow[start:readonly_start]
            readonly_job = workflow[readonly_start + 1 : end]
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
          CODEX_REVIEW_RUNNER_ENVIRONMENT: ${{{{ runner.environment }}}}
          CODEX_REVIEW_RUNNER_ARCH: ${{{{ runner.arch }}}}
        run: |
          python3 -m tests.run_hosted_no_child_fail_closed
      - name: Run deterministic independent supervisor tests
        working-directory: {skill_root}/scripts/independent_codex_pr_review
        env:
          CODEX_REVIEW_TEST_RUNTIME_PARENT: ${{{{ runner.temp }}}}
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
                self.assertNotIn(
                    "tests.run_readonly_install_deterministic_supervisor",
                    supervisor_job,
                )
                self.assertNotIn("tests.run_required_no_child_profile", supervisor_job)
                self.assertNotIn(
                    "CODEX_REVIEW_REQUIRE_LIVE_NO_CHILD_PROFILE",
                    supervisor_job,
                )
                self.assertIn("runs-on: macos-26", readonly_job)
                self.assertIn("timeout-minutes: 20", readonly_job)
                self.assertIn(
                    "Run deterministic supervisor from read-only install",
                    readonly_job,
                )
                self.assertIn(
                    f"REVIEW_SOURCE_RELATIVE: "
                    f"{skill_root}/scripts/independent_codex_pr_review",
                    readonly_job,
                )
                for requirement in (
                    "/usr/bin/sudo /usr/bin/mktemp -d "
                    "/Users/codex-review-readonly.XXXXXX",
                    "/usr/bin/sudo /usr/sbin/chown nobody:nobody",
                    '/usr/bin/sudo /usr/bin/ditto "$source_review_root" '
                    '"$isolated_source"',
                    "/usr/bin/sudo -u nobody /usr/bin/sandbox-exec -f",
                    "CODEX_REVIEW_TEST_RUNTIME_PARENT=",
                    "LOGNAME=nobody",
                    "USER=nobody",
                    "tests.run_readonly_install_deterministic_supervisor",
                ):
                    self.assertIn(requirement, readonly_job)
                self.assertIn("if: always()", readonly_job)

    def test_readonly_ci_deletes_only_a_proven_root_owned_outer_root(self) -> None:
        profile_contracts = {
            "canonical": "test",
            "private": "python-39-compatibility",
        }
        for profile, next_job in profile_contracts.items():
            workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(encoding="utf-8")
            start = workflow.index("  readonly_install_supervisor_tests:")
            end = workflow.index(f"\n  {next_job}:", start)
            readonly_job = workflow[start:end]
            with self.subTest(profile=profile):
                create_index = readonly_job.index(
                    'isolated_root="$(/usr/bin/sudo /usr/bin/mktemp -d '
                    '/Users/codex-review-readonly.XXXXXX)"'
                )
                recovery_index = readonly_job.index(
                    'echo "Read-only isolation recovery root: $isolated_root"'
                )
                path_guard_index = readonly_job.index(
                    '[[ ! "$isolated_root" =~ '
                    "^/Users/codex-review-readonly\\.[[:alnum:]]{6}$ ]]"
                )
                identity_index = readonly_job.index(
                    'isolated_object_id="$(/usr/bin/sudo /usr/bin/stat '
                    '-f \'%d:%i\' "$isolated_root")"'
                )
                payload_index = readonly_job.index(
                    "/usr/bin/sudo /usr/sbin/chown nobody:nobody "
                    '"$isolated_root/payload"'
                )
                immutable_index = readonly_job.index(
                    '/usr/bin/sudo /usr/bin/chflags uchg "$isolated_root"'
                )
                summary_create_index = readonly_job.index(
                    'summary_file="$(/usr/bin/mktemp '
                    '"$RUNNER_TEMP/codex-review-readonly-summary.XXXXXX")"'
                )
                summary_recovery_index = readonly_job.index(
                    'echo "Read-only supervisor summary file '
                    '(retained on failure): $summary_file"'
                )
                summary_validation_index = readonly_job.index(
                    '/bin/test -f "$summary_file"'
                )
                launch_index = readonly_job.index(
                    "/usr/bin/sudo -u nobody /usr/bin/sandbox-exec -f"
                )
                runner_failure_index = readonly_job.index(
                    "if (( runner_status != 0 )); then"
                )
                isolated_parser = (
                    '"$trusted_python" -I -B -S -c \'import json, pathlib, sys;'
                )
                parser_index = readonly_job.index(isolated_parser)
                evidence_index = readonly_job.index(
                    'expected = {"child_process_closure": "proven"'
                )
                evidence_failure_index = readonly_job.index(
                    "if (( summary_status != 0 )); then"
                )
                revalidation_index = readonly_job.index(
                    'current_object_id="$(/usr/bin/sudo /usr/bin/stat '
                    '-f \'%d:%i\' "$isolated_root")"'
                )
                clear_immutable_index = readonly_job.index(
                    '/usr/bin/sudo /usr/bin/chflags nouchg "$isolated_root"'
                )
                deletion = '/usr/bin/sudo /bin/rm -rf "$isolated_root"'
                delete_index = readonly_job.index(deletion)
                final_summary_index = readonly_job.index(
                    'final_summary_object_id="$(/usr/bin/stat -f '
                    '\'%d:%i\' "$summary_file")"'
                )
                summary_deletion = '/bin/rm "$summary_file"'
                summary_delete_index = readonly_job.index(summary_deletion)

                self.assertLess(create_index, recovery_index)
                self.assertLess(recovery_index, path_guard_index)
                self.assertLess(path_guard_index, identity_index)
                self.assertLess(identity_index, payload_index)
                self.assertLess(payload_index, immutable_index)
                self.assertLess(immutable_index, summary_create_index)
                self.assertLess(summary_create_index, summary_recovery_index)
                self.assertLess(summary_recovery_index, summary_validation_index)
                self.assertLess(summary_validation_index, launch_index)
                self.assertLess(launch_index, runner_failure_index)
                self.assertLess(runner_failure_index, parser_index)
                self.assertLess(parser_index, evidence_index)
                self.assertLess(evidence_index, evidence_failure_index)
                self.assertLess(evidence_failure_index, revalidation_index)
                self.assertLess(revalidation_index, clear_immutable_index)
                self.assertLess(clear_immutable_index, delete_index)
                self.assertLess(delete_index, final_summary_index)
                self.assertLess(final_summary_index, summary_delete_index)
                self.assertEqual(readonly_job.count(deletion), 1)
                self.assertEqual(readonly_job.count(summary_deletion), 1)
                self.assertEqual(readonly_job.count(isolated_parser), 1)
                self.assertIn(
                    'summary_file="$(/usr/bin/mktemp '
                    '"$RUNNER_TEMP/codex-review-readonly-summary.XXXXXX")"\n'
                    '          echo "Read-only supervisor summary file '
                    '(retained on failure): $summary_file"\n'
                    '          /bin/test -f "$summary_file"',
                    readonly_job,
                )
                self.assertNotIn(
                    '"$trusted_python" -B -c \'import json, pathlib, sys;',
                    readonly_job,
                )
                self.assertEqual(
                    readonly_job.count('/bin/test -f "$summary_file"'),
                    2,
                )
                self.assertEqual(
                    readonly_job.count('/bin/test ! -L "$summary_file"'),
                    1,
                )
                self.assertEqual(
                    readonly_job.count('/bin/test -L "$summary_file"'),
                    2,
                )

                self.assertNotIn(
                    '/usr/sbin/chown nobody:nobody "$isolated_root"\n',
                    readonly_job,
                )
                for protection in (
                    '/usr/bin/sudo /bin/test ! -L "$isolated_root"',
                    "test \"$(/usr/bin/sudo /usr/bin/stat -f '%u' "
                    '"$isolated_root")" = "0"',
                    "/usr/bin/sudo -u nobody /bin/test ! -w /Users",
                    '/usr/bin/sudo -u nobody /bin/test ! -w "$isolated_root"',
                    '/usr/bin/sudo -u nobody /bin/test ! -w "$RUNNER_TEMP"',
                    "(( (isolated_flags & 2) == 2 ))",
                    "set -o pipefail",
                    '| /usr/bin/tee "$summary_file" >/dev/null || runner_status=$?',
                    '[[ "$current_summary_object_id" != "$summary_object_id" ]]',
                    '[[ "$current_object_id" != "$isolated_object_id" ]]',
                    "[[ \"$(/usr/bin/sudo /usr/bin/stat -f '%f' "
                    '"$isolated_root")" != "$isolated_flags" ]]',
                    '[[ "$post_clear_object_id" != "$isolated_object_id" ]]',
                    "if (( root_cleanup_status != 0 ))",
                    '[[ "$final_summary_object_id" != "$summary_object_id" ]]',
                    "if (( summary_cleanup_status != 0 ))",
                    "object_pairs_hook=reject_duplicates",
                    'ValueError("duplicate JSON key")',
                    "set(payload) == set(expected)",
                    "type(payload[key]) is not type(value)",
                ):
                    self.assertIn(protection, readonly_job)
                for evidence in (
                    '"cleanup_failures": []',
                    '"cleanup_status": "complete"',
                    '"install_parent_is_sticky_world_writable": True',
                    '"primary_failure": None',
                    '"primary_status": "complete"',
                    '"release_tree_immutable": True',
                    '"release_tree_property": "object-identity-content-access-policy"',
                    '"retained_paths": []',
                    '"returncode": 0',
                    '"runtime_residue": []',
                    '"secondary_failures": []',
                    '"signal_number": None',
                    '"timed_out": False',
                ):
                    self.assertIn(evidence, readonly_job)
                self.assertGreaterEqual(
                    readonly_job.count("retained at $isolated_root"), 3
                )

    def test_readonly_ci_binds_profile_and_denies_executable_setid_modes(
        self,
    ) -> None:
        sandbox_profile = (
            SCRIPTS / "independent_codex_pr_review/tests/readonly_child_isolation.sb"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            sandbox_profile.splitlines(),
            [
                "(version 1)",
                "(allow default)",
                "(deny job-creation)",
                "(deny process-exec*",
                "  (file-mode #o4000 #o2000))",
            ],
        )
        self.assertNotIn("(literal ", sandbox_profile)

        profile_contracts = {
            "canonical": "test",
            "private": "python-39-compatibility",
        }
        for profile, next_job in profile_contracts.items():
            workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(encoding="utf-8")
            start = workflow.index("  readonly_install_supervisor_tests:")
            end = workflow.index(f"\n  {next_job}:", start)
            readonly_job = workflow[start:end]
            with self.subTest(profile=profile):
                trusted_python_probe_index = readonly_job.index(
                    'if ! /usr/bin/sudo -u nobody /bin/test -x "$trusted_python"; then'
                )
                source_root_path_index = readonly_job.index(
                    'source_review_root="$checkout_root/$REVIEW_SOURCE_RELATIVE"'
                )
                source_root_binding_index = readonly_job.index(
                    'source_root_binding="$(/usr/bin/stat -f '
                    '\'%d:%i:%p:%u:%g\' "$source_review_root")"'
                )
                source_profile_path_index = readonly_job.index(
                    'source_review_profile="$source_review_root/tests/'
                    'readonly_child_isolation.sb"'
                )
                source_copy_index = readonly_job.index(
                    '/usr/bin/sudo /usr/bin/ditto "$source_review_root" '
                    '"$isolated_source"'
                )
                source_postcopy_symlink_index = readonly_job.index(
                    'source_tree_postcopy_symlink="$(/usr/bin/find '
                    '"$source_review_root" -type l -print -quit)"'
                )
                isolated_postcopy_symlink_index = readonly_job.index(
                    'isolated_tree_postcopy_symlink="$(/usr/bin/sudo '
                    '/usr/bin/find "$isolated_source" -type l -print -quit)"'
                )
                source_custody_index = readonly_job.index(
                    '/usr/bin/sudo /usr/sbin/chown -R root:wheel "$isolated_source"'
                )
                source_readonly_index = readonly_job.index(
                    '/usr/bin/sudo /bin/chmod -R a+rX,a-w "$isolated_source"'
                )
                isolated_source_binding_index = readonly_job.index(
                    'isolated_source_binding="$(/usr/bin/sudo /usr/bin/stat '
                    '-f \'%d:%i:%u:%g:%Lp\' "$isolated_source")"'
                )
                isolated_root_traversal_index = readonly_job.index(
                    '/usr/bin/sudo /bin/chmod 0711 "$isolated_root"'
                )
                nobody_source_probe_index = readonly_job.index(
                    "/usr/bin/sudo -u nobody /bin/test -r "
                    '"$isolated_source/tests/'
                    'run_readonly_install_deterministic_supervisor.py"'
                )
                isolated_profile_path_index = readonly_job.index(
                    'review_profile="$isolated_root/readonly_child_isolation.sb"'
                )
                profile_copy_index = readonly_job.index(
                    '/usr/bin/sudo /bin/cp "$isolated_source_profile" "$review_profile"'
                )
                profile_binding_index = readonly_job.index(
                    'profile_binding="$(/usr/bin/sudo /usr/bin/stat '
                    '-f \'%d:%i:%u:%g:%Lp\' "$review_profile")"'
                )
                immutable_index = readonly_job.index(
                    '/usr/bin/sudo /usr/bin/chflags uchg "$isolated_root"'
                )
                policy_index = readonly_job.index(
                    "/usr/bin/grep -Fqx '(deny job-creation)'"
                )
                source_prelaunch_index = readonly_job.index(
                    'source_profile_prelaunch_binding="$(/usr/bin/stat'
                )
                prelaunch_index = readonly_job.index(
                    'profile_prelaunch_binding="$(/usr/bin/sudo /usr/bin/stat'
                )
                sandbox_index = readonly_job.index(
                    "/usr/bin/sudo -u nobody /usr/bin/sandbox-exec "
                    '-f "$review_profile" /usr/bin/env -i'
                )
                postrun_index = readonly_job.index(
                    'profile_postrun_binding="$(/usr/bin/sudo /usr/bin/stat'
                )

                self.assertLess(trusted_python_probe_index, source_root_path_index)
                self.assertLess(source_root_path_index, source_root_binding_index)
                self.assertLess(source_root_binding_index, source_profile_path_index)
                self.assertLess(source_profile_path_index, source_copy_index)
                self.assertLess(source_copy_index, source_postcopy_symlink_index)
                self.assertLess(
                    source_postcopy_symlink_index, isolated_postcopy_symlink_index
                )
                self.assertLess(isolated_postcopy_symlink_index, source_custody_index)
                self.assertLess(source_custody_index, source_readonly_index)
                self.assertLess(source_readonly_index, isolated_source_binding_index)
                self.assertLess(
                    isolated_source_binding_index, isolated_root_traversal_index
                )
                self.assertLess(
                    isolated_root_traversal_index, nobody_source_probe_index
                )
                self.assertLess(nobody_source_probe_index, isolated_profile_path_index)
                self.assertLess(isolated_profile_path_index, profile_copy_index)
                self.assertLess(profile_copy_index, profile_binding_index)
                self.assertLess(profile_binding_index, immutable_index)
                self.assertLess(immutable_index, policy_index)
                self.assertLess(policy_index, source_prelaunch_index)
                self.assertLess(source_prelaunch_index, prelaunch_index)
                self.assertLess(prelaunch_index, sandbox_index)
                self.assertLess(sandbox_index, postrun_index)
                self.assertEqual(
                    readonly_job.count("/usr/bin/sudo -u nobody /usr/bin/sandbox-exec"),
                    1,
                )
                self.assertNotIn(
                    "/usr/bin/sudo -u nobody /usr/bin/env -i",
                    readonly_job,
                )
                self.assertNotIn(
                    "/usr/bin/sudo -u nobody /usr/bin/ditto",
                    readonly_job,
                )
                self.assertNotIn(
                    '/usr/bin/ditto "$REVIEW_SOURCE_RELATIVE"',
                    readonly_job,
                )
                self.assertEqual(
                    readonly_job.count("/usr/bin/sudo /usr/sbin/chown nobody:nobody"),
                    1,
                )
                self.assertNotIn(
                    "/usr/bin/sudo /usr/sbin/chown -R nobody:nobody",
                    readonly_job,
                )
                self.assertEqual(
                    readonly_job.count("'%d:%i:%p:%u:%g' \"$source_review_root\")"),
                    4,
                )
                self.assertEqual(
                    readonly_job.count(
                        "/usr/bin/sudo /usr/bin/diff -qr "
                        '"$source_review_root" "$isolated_source" >/dev/null'
                    ),
                    3,
                )
                self.assertEqual(
                    readonly_job.count(
                        '$(/usr/bin/find "$source_review_root" -type l -print -quit)'
                    ),
                    2,
                )
                self.assertEqual(
                    readonly_job.count(
                        '$(/usr/bin/sudo /usr/bin/find "$isolated_source" '
                        "-type l -print -quit)"
                    ),
                    3,
                )
                for binding in (
                    'if ! /usr/bin/sudo -u nobody /bin/test -x "$trusted_python"; then',
                    "Trusted Python is not executable by nobody; retained at "
                    "$isolated_root",
                    'source_review_root="$checkout_root/$REVIEW_SOURCE_RELATIVE"',
                    'source_review_root_physical="$(cd "$source_review_root" '
                    '&& pwd -P)"',
                    '[[ "$source_review_root_physical" != "$source_review_root" ]]',
                    '/bin/test -d "$source_review_root"',
                    '/bin/test -L "$source_review_root"',
                    "# Bind source object identity/access policy separately "
                    "from copied content.",
                    'source_root_binding="$(/usr/bin/stat -f '
                    '\'%d:%i:%p:%u:%g\' "$source_review_root")"',
                    'source_tree_symlink="$(/usr/bin/find "$source_review_root" '
                    '-type l -print -quit)"',
                    'isolated_source="$isolated_root/source"',
                    '/usr/bin/sudo /bin/test ! -e "$isolated_source"',
                    '/usr/bin/sudo /usr/bin/ditto "$source_review_root" '
                    '"$isolated_source"',
                    'source_tree_postcopy_symlink="$(/usr/bin/find '
                    '"$source_review_root" -type l -print -quit)"',
                    'isolated_tree_postcopy_symlink="$(/usr/bin/sudo '
                    '/usr/bin/find "$isolated_source" -type l -print -quit)"',
                    '[[ -n "$source_tree_postcopy_symlink" ]]',
                    '[[ -n "$isolated_tree_postcopy_symlink" ]]',
                    '[[ "$source_root_postcopy_binding" != "$source_root_binding" ]]',
                    '[[ "$source_review_root_postcopy_physical" '
                    '!= "$source_review_root" ]]',
                    '/usr/bin/sudo /usr/bin/diff -qr "$source_review_root" '
                    '"$isolated_source" >/dev/null',
                    '/usr/bin/sudo /usr/sbin/chown -R root:wheel "$isolated_source"',
                    '/usr/bin/sudo /bin/chmod -RN "$isolated_source"',
                    '/usr/bin/sudo /bin/chmod -R a+rX,a-w "$isolated_source"',
                    'isolated_source_binding="$(/usr/bin/sudo /usr/bin/stat '
                    '-f \'%d:%i:%u:%g:%Lp\' "$isolated_source")"',
                    "test \"$(/usr/bin/sudo /usr/bin/stat -f '%u:%g:%Lp' "
                    '"$isolated_source")" = "0:0:555"',
                    "/usr/bin/sudo -u nobody /bin/test -r "
                    '"$isolated_source/tests/'
                    'run_readonly_install_deterministic_supervisor.py"',
                    '/usr/bin/sudo -u nobody /bin/test ! -w "$isolated_source"',
                    'sh "$isolated_source" "$trusted_python"',
                    '/bin/test -f "$source_review_profile"',
                    '/bin/test ! -L "$source_review_profile"',
                    'source_profile_binding="$(/usr/bin/stat -f '
                    '\'%d:%i:%u:%g:%Lp:%z:%m\' "$source_review_profile")"',
                    'review_profile="$isolated_root/readonly_child_isolation.sb"',
                    '/usr/bin/sudo /bin/test ! -e "$review_profile"',
                    '/usr/bin/sudo /bin/test ! -L "$review_profile"',
                    'isolated_source_profile="$isolated_source/tests/'
                    'readonly_child_isolation.sb"',
                    '/usr/bin/sudo /bin/cp "$isolated_source_profile" '
                    '"$review_profile"',
                    '/usr/bin/sudo /usr/sbin/chown root:wheel "$review_profile"',
                    '/usr/bin/sudo /bin/chmod -N "$review_profile"',
                    '/usr/bin/sudo /bin/chmod 0444 "$review_profile"',
                    '/usr/bin/sudo /bin/test -f "$review_profile"',
                    '/usr/bin/sudo /usr/bin/cmp -s "$source_review_profile" '
                    '"$review_profile"',
                    '/usr/bin/sudo /usr/bin/cmp -s "$isolated_source_profile" '
                    '"$review_profile"',
                    "test \"$(/usr/bin/sudo /usr/bin/stat -f '%u:%g:%Lp' "
                    '"$review_profile")" = "0:0:444"',
                    '/bin/test ! -w "$review_profile"',
                    '/usr/bin/sudo -u nobody /bin/test -r "$review_profile"',
                    '/usr/bin/sudo -u nobody /bin/test ! -w "$review_profile"',
                    '[[ "$source_profile_postcopy_binding" '
                    '!= "$source_profile_binding" ]]',
                    '[[ "$source_profile_prelaunch_binding" '
                    '!= "$source_profile_binding" ]]',
                    '[[ "$source_profile_postrun_binding" '
                    '!= "$source_profile_binding" ]]',
                    '[[ "$source_root_prelaunch_binding" != "$source_root_binding" ]]',
                    '[[ "$source_root_postrun_binding" != "$source_root_binding" ]]',
                    '[[ "$isolated_source_prelaunch_binding" '
                    '!= "$isolated_source_binding" ]]',
                    '[[ "$isolated_source_postrun_binding" '
                    '!= "$isolated_source_binding" ]]',
                    'isolated_tree_prelaunch_symlink="$(/usr/bin/sudo '
                    '/usr/bin/find "$isolated_source" -type l -print -quit)"',
                    '[[ -n "$isolated_tree_prelaunch_symlink" ]]',
                    'isolated_tree_postrun_symlink="$(/usr/bin/sudo '
                    '/usr/bin/find "$isolated_source" -type l -print -quit)"',
                    '[[ -n "$isolated_tree_postrun_symlink" ]]',
                    '[[ "$profile_prelaunch_binding" != "$profile_binding" ]]',
                    '[[ "$profile_postrun_binding" != "$profile_binding" ]]',
                ):
                    self.assertIn(binding, readonly_job)
                for prohibited_checkout_mutation in (
                    '\n          review_profile="$checkout_root/',
                    '/usr/sbin/chown root:wheel "$source_review_profile"',
                    '/bin/chmod -N "$source_review_profile"',
                    '/bin/chmod 0444 "$source_review_profile"',
                    '/usr/bin/chflags uchg "$source_review_profile"',
                    '/usr/bin/chflags uchg "$review_profile"',
                    "profile_flags",
                    "'%d:%i:%u:%g:%Lp:%f' \"$review_profile\"",
                ):
                    self.assertNotIn(prohibited_checkout_mutation, readonly_job)
                for policy_contract in (
                    "/usr/bin/grep -Fqx '(deny job-creation)'",
                    "/usr/bin/grep -Fqx '(deny process-exec*'",
                    "/usr/bin/grep -Fqx '  (file-mode #o4000 #o2000))'",
                    "/usr/bin/grep -Fq '(literal '",
                    "(( literal_profile_status != 1 ))",
                ):
                    self.assertIn(policy_contract, readonly_job)
                for removed_inventory_contract in (
                    "setuid_inventory",
                    "setuid_find_status",
                    "probe_nobody_executable",
                    "access_probe_stderr",
                    "profile_literal",
                ):
                    self.assertNotIn(removed_inventory_contract, readonly_job)

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
            "missing PR, unsupported host or integration, unavailable GitHub Codex service, or unsupported operating identity",
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
            "an authenticated provider rejection may prove no-start integration/service unavailability",
            "acknowledgement or run/review activity proves start",
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
            "No PR or proved integration/host/identity/service unavailability means effective double",
            interface,
        )
        self.assertIn("after service start means triple-inconclusive", interface)

    def test_github_codex_issue_comments_require_request_correlation(self) -> None:
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        for anchor in (
            "Keep a request ledger across the PR's issue-comment history",
            "does **not** resolve the older request",
            "the full exact current `headRefOid`",
            "the current request is the sole still-unresolved `@codex review` request",
            "A head marker does not relax either condition",
            "no other `@codex review` request intervened",
            "pair a response to the nearest request by timestamp alone",
            "an older-head request remains unresolved",
            "a full SHA proves only which head the response concerns, not which request caused it",
            "exact request comment ID/URL",
            "provider request/dispatch identity",
            "SHA-only delayed result while any older request remains unresolved",
            "even when the candidate names the full exact current `headRefOid`",
            "`triple-inconclusive`",
            "`commit_id == headRefOid`",
        ):
            self.assertIn(anchor, probes)

        self.assertIn(
            "the request-ledger and correlation rule",
            readiness,
        )
        self.assertIn(
            "An older request remains unresolved across a head change",
            readiness,
        )
        self.assertIn(
            "without the required correlation, that ambiguity is `triple-inconclusive`",
            readiness,
        )
        self.assertIn(
            "A terminal completion must bind through the exact request/run or the sole-unresolved/no-intervening fallback",
            readiness,
        )
        self.assertIn(
            "The full exact current SHA may corroborate artifact scope, but it does not identify which request caused the response",
            readiness,
        )
        self.assertIn(
            "Exact current-head SHA binding alone is not request binding for completion or no-start evidence",
            readiness,
        )
        self.assertIn(
            "A current-SHA marker cannot disambiguate which request caused a result",
            readiness,
        )
        self.assertNotIn(
            "the full exact current SHA, or the sole-unresolved-request fallback",
            readiness,
        )

    def test_current_sha_does_not_resolve_an_older_request(self) -> None:
        probes = (SKILL_ROOT / "references/github-pr-probes.md").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "SHA-only delayed terminal completion or no-start rejection while any older request remains unresolved",
            probes,
        )
        self.assertIn(
            "even when the terminal response names the current SHA",
            readiness,
        )
        self.assertIn(
            "an older request may execute after the push and review that same current head",
            readiness,
        )
        self.assertNotIn(
            "the SHA disambiguates any unresolved different-head request",
            probes,
        )
        self.assertNotIn(
            "full-current-SHA binding that disambiguates the head epoch",
            readiness,
        )

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
        )
        for content in identity_documents:
            self.assertIn("github.com", content)
            self.assertIn("chatgpt-codex-connector[bot]", content)
            self.assertIn("chatgpt-codex-connector", content)
        for content in (skill, readiness, probes, contracts, templates, egress):
            self.assertIn("Bot", content)
        self.assertIn('user.login == "chatgpt-codex-connector[bot]"', probes)
        self.assertIn('user.type == "Bot"', probes)
        self.assertIn('app.slug == "chatgpt-codex-connector"', probes)
        self.assertIn(
            "Accept a review artifact only when request isolation is proved, its `commit_id` equals `headRefOid`",
            probes,
        )
        for anchor in (
            "server `created_at`",
            "strictly later",
            "Evidence from an earlier request on the same unchanged head is stale",
        ):
            self.assertIn(anchor, probes)
        for anchor in (
            "complete terminal provider-authored",
            "findings payload",
            "fully paginated associated inline review comment",
            "terminal",
            "issue-comment body",
        ):
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
                with self.subTest(payload_anchor=anchor):
                    self.assertIn(anchor, content)
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
        if CI_PROFILE == "canonical":
            for content in (
                (REPO_ROOT / "README.md").read_text(encoding="utf-8"),
                (
                    REPO_ROOT
                    / "docs/project_journal/2026/07/"
                    / "2026-07-20-review-policy-migration-7f2001.md"
                ).read_text(encoding="utf-8"),
            ):
                self.assertIn("complete terminal provider-authored", content)
                self.assertIn("fully paginated associated inline", content)
                self.assertRegex(
                    content,
                    r"terminal(?: exact-bot)? issue-comment body",
                )

        for content in (readiness, probes, contracts):
            with self.subTest(check_only_document=content[:40]):
                self.assertIn("service-start evidence only", content)
                self.assertIn("never completes triple", content)
                self.assertIn('status == "completed"', content)
                self.assertIn('conclusion == "success"', content)
                self.assertIn("same-App check may be unrelated", content)
                self.assertIn("check success can coexist", content)
        self.assertNotIn("Accept a check/run only when", probes)

        for anchor in (
            "'repos/<owner>/<repo>/pulls/<number>/reviews?per_page=100'",
            "body}]'",
            "'repos/<owner>/<repo>/pulls/<number>/reviews/<review_id>/comments?per_page=100'",
            "pull_request_review_id",
            "'repos/<owner>/<repo>/issues/<number>/comments?per_page=100'",
            "COMMENTED",
            "APPROVED",
            "CHANGES_REQUESTED",
            "never `PENDING`",
        ):
            self.assertIn(anchor, probes)
        self.assertGreaterEqual(probes.count("--method GET --paginate --slurp"), 4)
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
        request_isolation_documents = {
            "skill": skill,
            "PR readiness": readiness,
            "GitHub probes": probes,
            "lane contracts": contracts,
            "prompt templates": templates,
            "repository policy": agents_policy,
            "skill interface": interface,
        }
        full_history_documents = {
            "PR readiness": readiness,
            "GitHub probes": probes,
            "lane contracts": contracts,
            "prompt templates": templates,
            "skill interface": interface,
        }
        if CI_PROFILE == "canonical":
            readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
            migration_journal = (
                REPO_ROOT
                / "docs/project_journal/2026/07/"
                / "2026-07-20-review-policy-migration-7f2001.md"
            ).read_text(encoding="utf-8")
            request_isolation_documents.update(
                {
                    "README": readme,
                    "migration journal": migration_journal,
                }
            )
            full_history_documents.update(
                {
                    "README": readme,
                    "migration journal": migration_journal,
                }
            )
        for name, content in request_isolation_documents.items():
            normalized = content.lower()
            with self.subTest(request_isolation_document=name):
                self.assertIn("at most one", normalized)
                self.assertIn("never post a second", normalized)
                self.assertIn("base-changed-same-head", normalized)
                self.assertIn("empty or anchor commit", normalized)
                self.assertIn(
                    "timestamps prove ordering, not request/run lineage",
                    normalized,
                )
        for name, content in full_history_documents.items():
            with self.subTest(full_history_document=name):
                self.assertIn("older request", content)
                self.assertIn("might overlap", content)
                self.assertIn("triple-inconclusive", content)
                self.assertIn("check/run", content)
                self.assertIn("started_at", content)
                self.assertIn(
                    "re-read complete authenticated request history immediately before",
                    content.lower(),
                )
        for content in (readiness, probes, contracts):
            self.assertIn("race", content)
        self.assertIn(
            "post the exact comment below only when complete authenticated history proves that no accepted exact request exists for the unchanged head",
            templates,
        )
        self.assertIn(
            "Otherwise reuse the one recorded request and do not post another",
            templates,
        )
        self.assertIn("non-null `started_at` strictly later than the request", probes)
        self.assertIn(
            "review/comment APIs expose no request/run identifier",
            readiness,
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
        post_request_anchor = "Otherwise post the one exact `@codex review` comment"
        for later_anchor in (run_lanes_anchor, read_state_anchor, post_request_anchor):
            self.assertLess(
                readiness.index(preflight_anchor), readiness.index(later_anchor)
            )

        for content in (agents_policy, skill, readiness, contracts, probes, templates):
            self.assertIn(
                "explicit-range-only standalone single/double with no selected pr",
                content.lower(),
            )

    def test_github_request_requires_terminal_local_lanes(self) -> None:
        documents = {
            "skill": SKILL_ROOT / "SKILL.md",
            "PR readiness": SKILL_ROOT / "references/pr-readiness.md",
            "lane contracts": SKILL_ROOT / "references/review-lane-contracts.md",
            "GitHub probes": SKILL_ROOT / "references/github-pr-probes.md",
            "prompt templates": SKILL_ROOT / "references/review-prompt-templates.md",
        }
        if CI_PROFILE == "canonical":
            documents["README"] = REPO_ROOT / "README.md"
        for name, path in documents.items():
            content = " ".join(path.read_text(encoding="utf-8").split()).lower()
            with self.subTest(policy_document=name):
                self.assertIn("github-request-before-local-terminal", content)
                self.assertIn("later local-lane completion does not cure", content)
                self.assertIn("terminal payload cannot count", content)
                self.assertIn("empty or anchor commit", content)

        interface = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        self.assertIn("github-request-before-local-terminal", interface)
        self.assertIn("both local terminals preceded", interface)
        self.assertIn("cannot be cured by later local completion", interface)
        self.assertIn("cannot be repeated on the unchanged head", interface)

        readiness = documents["PR readiness"].read_text(encoding="utf-8")
        self.assertLess(
            readiness.index("Run the requested local lanes"),
            readiness.index("Otherwise post the one exact `@codex review` comment"),
        )
        self.assertIn(
            "only after both local lanes are terminal",
            readiness,
        )


if __name__ == "__main__":
    unittest.main()
