from __future__ import annotations

import inspect
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterable, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
SKILL_SCOPE_ROOT = SKILL_ROOT.parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import (  # noqa: E402
    claude_capabilities,
    claude_linux,
    claude_refresh_lock,
    providers,
    workspace as workspace_runtime,
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
CI_PROFILE_BY_SKILL_LAYOUT = {
    pathlib.Path("skills/review-orchestration-playbook"): "canonical",
    pathlib.Path(
        "personal_codex/skills/review-orchestration-playbook"
    ): "private",
}


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


_LFS_V1_ALIASES = {
    b"http://git-media.io/v/2",
    b"https://hawser.github.com/spec/v1",
    b"https://git-lfs.github.com/spec/v1",
}
_LFS_OID_RE = re.compile(br"sha256:[0-9a-f]{64}\Z")
_LFS_EXTENSION_PREFIX_RE = re.compile(br"ext-\d{1}-\w+")
_LFS_SIZE_RE = re.compile(br"[+-]?[0-9]+\Z")


def _go_is_space(character: str) -> bool:
    codepoint = ord(character)
    if codepoint < 128:
        return character in "\t\n\v\f\r "
    if 0xDC80 <= codepoint <= 0xDCFF:
        return False
    return character.isspace()


def _go_bytes_trim_space(payload: bytes) -> bytes:
    text = payload.decode("utf-8", errors="surrogateescape")
    start = 0
    end = len(text)
    while start < end and _go_is_space(text[start]):
        start += 1
    while end > start and _go_is_space(text[end - 1]):
        end -= 1
    return text[start:end].encode("utf-8", errors="surrogateescape")


def _go_scan_lines(payload: bytes) -> list[bytes]:
    if not payload:
        return []
    records = payload.split(b"\n")
    if payload.endswith(b"\n"):
        records.pop()
    return [record[:-1] if record.endswith(b"\r") else record for record in records]


def _git_lfs_3_7_1_reference_pointer_gate(payload: bytes) -> bool:
    if not payload or len(payload) >= 1024:
        return False

    data = _go_bytes_trim_space(payload)
    if not re.search(br"git-media|hawser|git-lfs", data):
        return False

    pointer_keys = (b"version", b"oid", b"size")
    core: dict[bytes, bytes] = {}
    extensions: dict[bytes, bytes] = {}
    line = 0
    for record in _go_scan_lines(data):
        if not record:
            continue
        parts = record.split(b" ", 1)
        if len(parts) != 2 or line >= len(pointer_keys):
            return False
        key, value = parts
        if key != pointer_keys[line]:
            if _LFS_EXTENSION_PREFIX_RE.match(key) is None:
                return False
            extensions[key] = value
            continue
        core[key] = value
        line += 1

    if core.get(b"version") not in _LFS_V1_ALIASES:
        return False
    if _LFS_OID_RE.fullmatch(core.get(b"oid", b"")) is None:
        return False
    size_bytes = core.get(b"size", b"")
    if _LFS_SIZE_RE.fullmatch(size_bytes) is None:
        return False
    size = int(size_bytes, 10)
    if size < 0 or size > (1 << 63) - 1:
        return False

    priorities: set[int] = set()
    for key, value in extensions.items():
        key_parts = key.split(b"-", 2)
        if len(key_parts) != 3 or key_parts[0] != b"ext":
            return False
        priority = int(key_parts[1], 10)
        if priority < 0 or priority in priorities:
            return False
        priorities.add(priority)
        if _LFS_OID_RE.fullmatch(value) is None:
            return False
    return True


def _bounded_final_reader_model(
    chunks: tuple[bytes, ...],
    *,
    eof: bool,
) -> tuple[str, int, str]:
    remaining = 65_536
    admitted = 0
    for chunk in chunks:
        if remaining == 0:
            if chunk:
                return "limit-terminated/inconclusive", admitted, "byte"
            continue
        accepted = min(len(chunk), remaining)
        admitted += accepted
        remaining -= accepted
        if accepted < len(chunk):
            return "limit-terminated/inconclusive", admitted, "byte"
    if remaining == 0:
        if eof:
            return "seal-eligible", admitted, "eof"
        return "incomplete/inconclusive", admitted, "open"
    if not eof:
        return "incomplete/inconclusive", admitted, "open"
    if admitted == 0:
        return "invalid/inconclusive", admitted, "not-needed"
    return "seal-eligible", admitted, "not-needed"


def _unique_parent_path_accounting(
    raw_paths: Iterable[Sequence[int]],
    *,
    max_path_bytes: int = 128 * 1024 * 1024,
    max_depth: int = 100_000,
    max_integer: int = (1 << 63) - 1,
    parent_count_cap: int = (1 << 63) - 1,
    parent_path_bytes_cap: int = (1 << 63) - 1,
    parent_accounting_cap: int = (1 << 63) - 1,
    projection_inputs: dict[str, object] | None = None,
) -> dict[str, int | str]:
    unique_parent_count = 0
    unique_parent_path_bytes = 0
    previous_raw_path: bytes | None = None
    peak_retained_raw_bytes = 0
    peak_parent_depth = 0
    consumed_paths = 0

    if projection_inputs is not None:
        baseline_projection = _targeted_manifest_accounting_model(
            unique_parent_directory_count=0,
            unique_parent_path_bytes=0,
            **projection_inputs,
        )
        if baseline_projection["status"] != "admitted":
            return {
                "status": str(baseline_projection["status"]),
                "consumed_paths": 0,
                "scanned_raw_bytes": 0,
                "unique_parent_directory_count": 0,
                "unique_parent_path_bytes": 0,
            }

    for raw_path in raw_paths:
        consumed_paths += 1
        if (
            projection_inputs is not None
            and consumed_paths > projection_inputs.get("entry_count")
        ):
            return {
                "status": "fail-closed-entry-count-mismatch",
                "consumed_paths": consumed_paths,
            }
        raw_path_length = len(raw_path)
        if (
            raw_path_length == 0
            or raw_path_length > max_path_bytes
            or max_depth < 1
        ):
            return {
                "status": "fail-closed-path-bound",
                "consumed_paths": consumed_paths,
                "scanned_raw_bytes": 0,
            }

        current_raw_path = bytearray()
        previous_was_slash = False
        current_parent_depth = 0
        order_is_greater = previous_raw_path is None
        common_raw_prefix_active = previous_raw_path is not None

        for index in range(raw_path_length):
            byte = raw_path[index]
            if not isinstance(byte, int) or not 0 <= byte <= 255:
                return {
                    "status": "fail-closed-path-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            current_raw_path.append(byte)

            if index == 0 and byte == 0x2F:
                return {
                    "status": "fail-closed-path-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": 1,
                }

            if previous_raw_path is not None and not order_is_greater:
                if index >= len(previous_raw_path):
                    order_is_greater = True
                    common_raw_prefix_active = False
                else:
                    previous_byte = previous_raw_path[index]
                    if byte < previous_byte:
                        return {
                            "status": "fail-closed-path-order",
                            "consumed_paths": consumed_paths,
                            "scanned_raw_bytes": index + 1,
                        }
                    if byte > previous_byte:
                        order_is_greater = True
                        common_raw_prefix_active = False

            if byte != 0x2F:
                previous_was_slash = False
                continue
            if index == raw_path_length - 1:
                return {
                    "status": "fail-closed-path-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                    "retained_parent_depth": current_parent_depth,
                }
            if previous_was_slash:
                return {
                    "status": "fail-closed-path-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                    "retained_parent_depth": current_parent_depth,
                }
            if current_parent_depth + 1 >= max_depth:
                return {
                    "status": "fail-closed-path-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                    "retained_parent_depth": current_parent_depth,
                }
            current_parent_depth += 1
            previous_was_slash = True

            shared_parent = (
                common_raw_prefix_active
                and previous_raw_path is not None
                and index < len(previous_raw_path)
                and previous_raw_path[index] == 0x2F
            )
            if shared_parent:
                continue

            if unique_parent_count >= max_integer:
                return {
                    "status": "fail-closed-overflow",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            unique_parent_count += 1
            if unique_parent_path_bytes > max_integer - index:
                return {
                    "status": "fail-closed-overflow",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            unique_parent_path_bytes += index
            if unique_parent_count > max_integer // 192:
                return {
                    "status": "fail-closed-overflow",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            parent_record_bytes = 192 * unique_parent_count
            if unique_parent_path_bytes > max_integer - parent_record_bytes:
                return {
                    "status": "fail-closed-overflow",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            if (
                unique_parent_count > parent_count_cap
                or unique_parent_path_bytes > parent_path_bytes_cap
                or unique_parent_path_bytes + parent_record_bytes
                > parent_accounting_cap
            ):
                return {
                    "status": "fail-closed-parent-accounting-bound",
                    "consumed_paths": consumed_paths,
                    "scanned_raw_bytes": index + 1,
                }
            if projection_inputs is not None:
                projection = _targeted_manifest_accounting_model(
                    unique_parent_directory_count=unique_parent_count,
                    unique_parent_path_bytes=unique_parent_path_bytes,
                    **projection_inputs,
                )
                if projection["status"] != "admitted":
                    return {
                        "status": str(projection["status"]),
                        "consumed_paths": consumed_paths,
                        "scanned_raw_bytes": index + 1,
                        "unique_parent_directory_count": unique_parent_count,
                        "unique_parent_path_bytes": unique_parent_path_bytes,
                    }

        if previous_raw_path is not None and not order_is_greater:
            return {
                "status": "fail-closed-path-order",
                "consumed_paths": consumed_paths,
                "scanned_raw_bytes": raw_path_length,
            }

        peak_retained_raw_bytes = max(
            peak_retained_raw_bytes,
            len(previous_raw_path or b"") + len(current_raw_path),
        )
        peak_parent_depth = max(peak_parent_depth, current_parent_depth)
        previous_raw_path = bytes(current_raw_path)

    if projection_inputs is not None:
        expected_entry_count = projection_inputs.get("entry_count")
        if consumed_paths != expected_entry_count:
            return {
                "status": "fail-closed-entry-count-mismatch",
                "consumed_paths": consumed_paths,
            }

    return {
        "status": "ok",
        "unique_parent_directory_count": unique_parent_count,
        "unique_parent_path_bytes": unique_parent_path_bytes,
        "consumed_paths": consumed_paths,
        "peak_retained_raw_bytes": peak_retained_raw_bytes,
        "peak_parent_depth": peak_parent_depth,
    }


def _targeted_manifest_accounting_model(
    *,
    entry_count: int,
    tree_metadata_bytes: int,
    unique_parent_directory_count: int,
    unique_parent_path_bytes: int,
    registration_descendant_count: int,
    registration_path_bytes: int,
    a_checkout: int,
    checkout_base_bound_without_parents: int,
    git_admin_bound: int,
    checkout_filesystem: str,
    manifest_filesystem: str,
    git_filesystem: str,
    retention_filesystem: str,
    process_envelope: int = 257 * 1024 * 1024,
    checkout_cap: int = 1024 * 1024 * 1024,
    filesystem_headroom: dict[str, int] | None = None,
    actual_payload_bytes: int | None = None,
    actual_temp_allocation: int | None = None,
    actual_published_allocation: int | None = None,
    actual_control_allocation: int | None = None,
    max_integer: int = (1 << 63) - 1,
) -> dict[str, object]:
    registration_descendant_count_cap = 16
    registration_path_bytes_cap = 4096
    if (
        registration_descendant_count < 0
        or registration_path_bytes < 0
        or registration_descendant_count > registration_descendant_count_cap
        or registration_path_bytes > registration_path_bytes_cap
    ):
        return {"status": "fail-closed-registration-bound-exceeded"}

    def checked_add(*values: int) -> int:
        result = 0
        for value in values:
            if value < 0 or result > max_integer - value:
                raise OverflowError
            result += value
        return result

    def checked_mul(left: int, right: int) -> int:
        if left < 0 or right < 0:
            raise OverflowError
        if left and right > max_integer // left:
            raise OverflowError
        return left * right

    def checked_align_up(value: int, alignment: int) -> int:
        if alignment < 4096:
            raise OverflowError
        return checked_mul(
            checked_add(value, alignment - 1) // alignment,
            alignment,
        )

    if manifest_filesystem != checkout_filesystem:
        return {"status": "fail-closed-cross-filesystem-mismatch"}

    try:
        checkout_entry_bound = checked_add(
            1,
            entry_count,
            unique_parent_directory_count,
            3,
        )
        entry_bound = checked_add(
            checkout_entry_bound,
            1,
            registration_descendant_count_cap,
        )
        payload_bound = checked_add(
            4096,
            tree_metadata_bytes,
            unique_parent_path_bytes,
            4096,
            registration_path_bytes_cap,
            checked_mul(192, entry_bound),
        )
        file_bound = checked_add(
            checked_align_up(payload_bound, a_checkout),
            a_checkout,
        )
        control_bound = checked_mul(2, a_checkout)
        targeted_bound = checked_add(
            checked_mul(2, file_bound),
            control_bound,
        )
        checkout_parent_allocation_bound = checked_mul(
            a_checkout,
            unique_parent_directory_count,
        )
        checkout_root_bound = checked_add(
            checkout_base_bound_without_parents,
            checkout_parent_allocation_bound,
            targeted_bound,
        )
        checkout_accounting_bound = checked_add(
            checkout_root_bound,
            git_admin_bound,
        )
    except OverflowError:
        return {"status": "fail-closed-overflow"}

    actuals = (
        (actual_payload_bytes, payload_bound),
        (actual_temp_allocation, file_bound),
        (actual_published_allocation, file_bound),
        (actual_control_allocation, control_bound),
    )
    if any(actual is not None and actual > bound for actual, bound in actuals):
        return {"status": "fail-closed-bound-exceeded"}

    physical_projection: dict[str, int] = {}
    try:
        for filesystem, charge in (
            (retention_filesystem, process_envelope),
            (checkout_filesystem, checkout_root_bound),
            (git_filesystem, git_admin_bound),
        ):
            physical_projection[filesystem] = checked_add(
                physical_projection.get(filesystem, 0),
                charge,
            )
    except OverflowError:
        return {"status": "fail-closed-overflow"}

    status = (
        "admitted"
        if checkout_accounting_bound <= checkout_cap
        else "blocked-worktree-capacity"
    )
    if status == "admitted" and filesystem_headroom is not None:
        if any(
            projected > filesystem_headroom.get(filesystem, -1)
            for filesystem, projected in physical_projection.items()
        ):
            status = "blocked-worktree-capacity"

    return {
        "status": status,
        "unique_parent_directory_count": unique_parent_directory_count,
        "unique_parent_path_bytes": unique_parent_path_bytes,
        "checkout_manifest_entry_bound": checkout_entry_bound,
        "registration_descendant_count_cap": registration_descendant_count_cap,
        "registration_path_bytes_cap": registration_path_bytes_cap,
        "targeted_manifest_entry_bound": entry_bound,
        "targeted_manifest_payload_bound": payload_bound,
        "targeted_manifest_file_bound": file_bound,
        "targeted_manifest_control_bound": control_bound,
        "targeted_manifest_bound": targeted_bound,
        "checkout_parent_allocation_bound": checkout_parent_allocation_bound,
        "checkout_root_bound": checkout_root_bound,
        "checkout_accounting_bound": checkout_accounting_bound,
        "logical_ledgers": {
            "process": process_envelope,
            "checkout": checkout_accounting_bound,
        },
        "targeted_manifest_ledger": "checkout",
        "targeted_manifest_filesystem": checkout_filesystem,
        "physical_projection": physical_projection,
    }


_ManifestIdentity = tuple[str, int, int, int, int, str]


def _targeted_cleanup_resume_model(
    manifest: dict[bytes, _ManifestIdentity],
    observed: dict[bytes, _ManifestIdentity],
    *,
    deleted_by_live_chain: frozenset[bytes] = frozenset(),
    continuous_live_custody: bool,
    exact_open_descriptions: bool = True,
    same_ofd_lock: bool = True,
    namespace_write_excluded: bool = True,
    path_reopened: bool = False,
    parent_identity_matches: bool = True,
    missing_side_absent: bool = True,
    alias_absent: bool = True,
    cross_crash_backend_opted_in: bool = False,
    backend_stable_handles_for_all: bool = False,
    backend_absence_proof: bool = False,
    backend_atomic_capture_or_exclusion: bool = False,
    sealed_final: bool = True,
) -> tuple[str, str, bool]:
    manual = (
        "manual-recovery-required",
        "full-grouped-charges-retained",
        sealed_final,
    )
    live_authority = (
        continuous_live_custody
        and exact_open_descriptions
        and same_ofd_lock
        and namespace_write_excluded
        and not path_reopened
    )
    backend_authority = (
        cross_crash_backend_opted_in
        and backend_stable_handles_for_all
        and backend_absence_proof
        and backend_atomic_capture_or_exclusion
    )
    if not parent_identity_matches or not missing_side_absent or not alias_absent:
        return manual
    if not live_authority and not backend_authority:
        return manual
    if not observed.keys() <= manifest.keys():
        return manual
    if any(manifest[path] != identity for path, identity in observed.items()):
        return manual
    missing = manifest.keys() - observed.keys()
    if live_authority and not missing <= deleted_by_live_chain:
        return manual
    if b"" not in observed:
        return "double-absence-barrier", "charged-until-exact-settlement", sealed_final
    authority = "live-custody" if live_authority else "opt-in-backend"
    return f"resume-{authority}", "charged-until-exact-settlement", sealed_final


def _claude_auth_repository_policy_files(
    repo_root: pathlib.Path,
    profile: str,
) -> dict[str, str]:
    policy_paths: dict[str, pathlib.Path] = {}
    if profile == "canonical":
        policy_paths = {
            "AGENTS.md": repo_root / "AGENTS.md",
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
        name: path.read_text(encoding="utf-8")
        for name, path in policy_paths.items()
    }


class RepositoryContractTest(unittest.TestCase):
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
        with (SKILL_SCOPE_ROOT / "agents/reviewer.toml").open("rb") as handle:
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
        self.assertIn("current-account `Claude Code-credentials`", helper_contract)
        self.assertIn("helper-controlled proxy", helper_contract)
        self.assertIn(">=2.1.211,<3.0.0", helper_contract)
        self.assertIn("Linux and WSL2", helper_contract)
        self.assertIn("does not read or import `~/.claude.json`", helper_contract)
        self.assertIn(
            "rechecks both the current-account Keychain item and the empirically "
            "compatible `.claude/.credentials.json`",
            skill,
        )
        self.assertIn(
            "local-login selection is limited to that Keychain item and pwd-home "
            "credential file",
            skill,
        )
        self.assertNotIn("Keychain is the only local-login source", skill)
        self.assertIn("Before every Claude model attempt", helper_contract)
        self.assertIn("bounded machine-readable `reason`", helper_contract)
        self.assertNotIn("requires `ANTHROPIC_API_KEY`", skill)

        providers_source = (SCRIPTS / "review_runtime/providers.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(".claude.json", providers_source)

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

    def test_claude_auth_carriers_refresh_without_a_freshness_gate(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        helper_contract = (SKILL_ROOT / "references/helper-contract.md").read_text(
            encoding="utf-8"
        )
        runtime_trust = (
            SKILL_ROOT / "references/claude-runtime-trust.md"
        ).read_text(encoding="utf-8")

        egress_consent = (
            SKILL_ROOT / "references/egress-consent.md"
        ).read_text(encoding="utf-8")
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

        attempt_source = inspect.getsource(providers._claude_attempt)
        pwd_home_source = inspect.getsource(providers._claude_pwd_home)
        select_source = inspect.getsource(providers._select_claude_macos_credential)
        validate_source = inspect.getsource(
            providers._validate_claude_local_credential
        )
        macos_runtime_source = inspect.getsource(
            providers._claude_keychain_runtime
        ) + inspect.getsource(providers._claude_keychain_runtime_selected)
        macos_persist_source = inspect.getsource(
            providers._persist_claude_macos_refreshed_credential
        ) + inspect.getsource(
            providers._persist_claude_macos_refreshed_credential_impl
        )
        macos_recovery_report_source = inspect.getsource(
            providers._record_claude_secondary_persistence_failure
        )
        run_review_source = inspect.getsource(providers.run_review)
        auth_outcome_source = inspect.getsource(
            providers._finish_claude_auth_required
        )
        post_inspection_auth_source = inspect.getsource(
            providers._claude_auth_rejection_after_credential_inspection
        )
        linux_runtime_source = inspect.getsource(
            providers._claude_linux_review_runtime
        )
        linux_command_source = inspect.getsource(claude_linux.build_sandbox_command)
        keychain_write_source = inspect.getsource(
            providers._write_claude_keychain_credential
        )
        file_write_source = inspect.getsource(
            providers._write_claude_file_credential
        )
        linux_write_source = inspect.getsource(
            claude_linux._writeback_refreshed_credential_impl
        )
        linux_staging_source = inspect.getsource(
            claude_linux.stage_claude_credentials
        )
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
        self.assertIn("on_process_started=writer_started.set", attempt_source)
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
            "SKILL.md": skill,
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
            "SKILL.md": skill,
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
            "SKILL.md": skill,
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
            "SKILL.md": skill,
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
            "durably stages its exact payload",
            skill,
        )
        self.assertIn(
            "later requests are NACKed before callbacks",
            skill,
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
        self.assertIn('env.get("ANTHROPIC_API_KEY")', attempt_source)

        self.assertIn('"phase": "blocked-authentication"', auth_outcome_source)
        self.assertIn("CLAUDE_AUTH_LOGIN_ACTION", auth_outcome_source)
        self.assertIn("_finish_claude_auth_required", run_review_source)
        self.assertIn("validate_external_workspace", run_review_source)
        self.assertIn("sensitive-content and escaping-symlink checks passed", run_review_source)
        self.assertIn(
            "_claude_supported_failure_category",
            post_inspection_auth_source,
        )
        self.assertIn("requested_model=model", post_inspection_auth_source)

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
        self.assertIn("certified 5-second heartbeat", current_policy)
        self.assertIn("both carriers", current_policy)
        self.assertIn("inspection-inconclusive", current_policy)
        self.assertIn("Access-token expiry alone is not login expiry", current_policy)
        self.assertIn("blocked-authentication", current_policy)
        self.assertIn("claude auth login", current_policy)
        self.assertIn(
            "unstructured HTTP 401 or authentication fragments remain "
            "`inspection-inconclusive`",
            skill,
        )
        self.assertIn("strict request/model-bound result envelope", skill)
        self.assertIn(
            "override credential reinspection and establish `blocked-authentication`",
            skill,
        )
        self.assertNotIn(
            "actually rejected local-login authentication (`Login expired`, "
            "HTTP 401, or refresh failure)",
            skill,
        )
        for policy in (skill, helper_contract, runtime_trust):
            self.assertIn("claude auth login", policy)
            self.assertIn("ANTHROPIC_API_KEY", policy)
            self.assertIn("unset or replace", policy)
        self.assertIn("secure Claude runtime is deterministically absent/unavailable", current_policy)
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
        cli_denies = set(
            claude_linux.CLAUDE_LINUX_REVIEW_DISALLOWED_TOOLS.split(",")
        )
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

    def test_ci_targets_only_the_canonical_runtime_and_tests(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertIn("review-orchestration-playbook/tests", workflow)
        self.assertNotIn("external-review-playbook", workflow)
        self.assertNotIn("copilot-review-playbook", workflow)

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

    def test_ci_contract_carries_every_reviewed_profile_snapshot(self) -> None:
        self.assertEqual(
            set(CI_PROFILE_BY_SKILL_LAYOUT.values()),
            {"canonical", "private"},
        )
        for profile in CI_PROFILE_BY_SKILL_LAYOUT.values():
            with self.subTest(profile=profile):
                self.assertTrue((CI_FIXTURE_ROOT / f"{profile}.yml").is_file())

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

    def test_broker_reproducibility_never_runs_checkout_code_as_root(self) -> None:
        script = (
            SCRIPTS / "build_claude_keychain_broker_macos.sh"
        ).read_text(encoding="utf-8")
        for profile in ("canonical", "private"):
            workflow = (CI_FIXTURE_ROOT / f"{profile}.yml").read_text(
                encoding="utf-8"
            )
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

    def test_independent_codex_supervisor_is_self_contained_and_bounded(
        self,
    ) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        entrypoint = tool_root / "independent-codex-pr-review"
        readme = (tool_root / "README.md").read_text(encoding="utf-8")
        constants = (tool_root / "review_supervisor/constants.py").read_text(
            encoding="utf-8"
        )
        workflow = (SKILL_SCOPE_ROOT / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertTrue(entrypoint.is_file())
        self.assertTrue(entrypoint.stat().st_mode & 0o111)
        self.assertTrue((tool_root / "review_supervisor/cli.py").is_file())
        self.assertTrue((tool_root / "tests/test_supervisor.py").is_file())
        self.assertEqual(
            entrypoint.read_text(encoding="utf-8").splitlines()[0],
            "#!/usr/bin/env python3.13",
        )
        self.assertIn('MODEL = "gpt-5.6-sol"', constants)
        self.assertIn('REASONING_EFFORT = "xhigh"', constants)
        self.assertIn("MAX_EVIDENCE_BUNDLE_BYTES", constants)
        self.assertIn("app-server", readme)
        self.assertIn("owner-only `CODEX_HOME`", readme)
        self.assertIn("bounded evidence bundle", readme)
        self.assertIn("sealed", readme)
        self.assertIn("settlement", readme)
        self.assertIn("independent_supervisor_tests", workflow)
        self.assertIn('python-version: "3.13"', workflow)
        self.assertIn(
            "scripts/independent_codex_pr_review",
            workflow,
        )
        for value in (readiness, contracts):
            self.assertIn("independent-codex-pr-review", value)
            self.assertIn("app-server", value)
            self.assertIn("gpt-5.6-sol", value)
            self.assertIn("xhigh", value)
            self.assertNotIn("codex exec --ephemeral", value)

    def test_checkout_charge_release_requires_durable_namespace_barriers(
        self,
    ) -> None:
        candidates = {
            "pr-readiness": (
                SKILL_ROOT / "references/pr-readiness.md"
            ).read_text(encoding="utf-8"),
            "review-lane-contracts": (
                SKILL_ROOT / "references/review-lane-contracts.md"
            ).read_text(encoding="utf-8"),
        }

        for name, content in candidates.items():
            with self.subTest(contract=name):
                retained = content.index(
                    "Before destructive checkout cleanup when checkout side effects may exist"
                )
                retained_readback = content.index(
                    "exactly read back a non-TTL `retained-worktree` record",
                    retained,
                )
                cleanup = content.index(
                    "Before destructive checkout cleanup, require",
                    retained_readback,
                )
                checkout_parent = content.index(
                    "exact checkout parent directory",
                    cleanup,
                )
                git_admin_parent = content.index(
                    "common Git `worktrees` directory",
                    checkout_parent,
                )
                identity_check = content.index(
                    "bind and revalidate both directory identities before any removal decision",
                    git_admin_parent,
                )
                removal = content.index(
                    "`git worktree remove --force <exact-path>`",
                    identity_check,
                )
                directory_fsyncs = content.index(
                    "both already-open parent", removal
                )
                absence_recheck = content.index(
                    "re-prove both exact names",
                    directory_fsyncs,
                )
                settlement = content.index(
                    "atomically persist, file/directory `fsync`, and exactly read back",
                    absence_recheck,
                )
                charge_release = content.lower().index(
                    "checkout charges are released only at that exact settlement readback",
                    settlement,
                )

                self.assertLess(retained, retained_readback)
                self.assertLess(retained_readback, cleanup)
                self.assertLess(cleanup, checkout_parent)
                self.assertLess(checkout_parent, git_admin_parent)
                self.assertLess(git_admin_parent, identity_check)
                self.assertLess(identity_check, removal)
                self.assertLess(removal, directory_fsyncs)
                self.assertLess(directory_fsyncs, absence_recheck)
                self.assertLess(absence_recheck, settlement)
                self.assertLess(settlement, charge_release)

                failure = content.index("Any", charge_release)
                failure_contract = content[failure : failure + 900]
                self.assertIn("full grouped checkout charges", failure_contract)
                self.assertIn("already-durable `retained-worktree`", failure_contract)
                self.assertIn("`cleanup-warning`", failure_contract)
                self.assertIn("`blocked-worktree-capacity`", failure_contract)
                self.assertIn("blocks every later worktree admission", failure_contract)

    def test_checkout_cleanup_recovery_covers_all_authenticated_states(
        self,
    ) -> None:
        candidates = {
            "pr-readiness": (
                SKILL_ROOT / "references/pr-readiness.md"
            ).read_text(encoding="utf-8"),
            "review-lane-contracts": (
                SKILL_ROOT / "references/review-lane-contracts.md"
            ).read_text(encoding="utf-8"),
        }

        for name, content in candidates.items():
            with self.subTest(contract=name):
                cleanup = content.index(
                    "Before destructive checkout cleanup, require"
                )
                authentication = content.index(
                    "authenticate that outstanding durable `retained-worktree` record",
                    cleanup,
                )
                parent_descriptors = content.index(
                    "already-open or freshly reopened no-follow stable descriptors",
                    authentication,
                )
                identity_check = content.index(
                    "bind and revalidate both directory identities before any removal decision",
                    parent_descriptors,
                )
                namespace_probe = content.index(
                    "Probe the two recorded names relative to those descriptors",
                    identity_check,
                )
                custody = content.index(
                    "Recovery is idempotent only while", namespace_probe
                )
                double_absence = content.index("both exact names are absent", custody)
                both_present = content.index(
                    "both are present with their recorded identities", double_absence
                )
                checkout_only = content.index(
                    "checkout-present/registration-absent", both_present
                )
                registration_only = content.index(
                    "checkout-absent/registration-present", checkout_only
                )
                manifest = content.index(
                    "construct a complete descendant manifest", registration_only
                )
                same_live_input = content.index(
                    "same-live-custody revalidation input, not generic successor authority",
                    manifest,
                )
                manifest_charge = content.index(
                    "`targeted_manifest_bound`", same_live_input
                )
                intent = content.index(
                    "branch-specific `targeted-removal-intent`", manifest_charge
                )
                intent_readback = content.index(
                    "Only after exact readback of the intent and manifest", intent
                )
                destructive_leaf = content.index(
                    "delete the checkout `.git` marker", intent_readback
                )
                deletion_progress = content.index(
                    "records each successful unlink", destructive_leaf
                )
                retry = content.index(
                    "same uninterrupted owner/guardian chain", deletion_progress
                )
                moved_out = content.index(
                    "moved-out object and is not deletion proof", retry
                )
                chain_death = content.index(
                    "chain dies or loses any exact description/lock", moved_out
                )
                manual = content.index("`manual-recovery-required`", chain_death)
                no_more_deletion = content.index(
                    "no further unlink or rename", manual
                )
                optional_backend = content.index(
                    "optional cross-crash backend is opt-in", no_more_deletion
                )
                broad_prune = content.index("`git worktree prune`", optional_backend)
                parent_fsyncs = content.index("both already-open parent", broad_prune)
                settlement = content.index(
                    "`checkout_settlement=exact`", parent_fsyncs
                )

                ordered = (
                    cleanup,
                    authentication,
                    parent_descriptors,
                    identity_check,
                    namespace_probe,
                    custody,
                    double_absence,
                    both_present,
                    checkout_only,
                    registration_only,
                    manifest,
                    same_live_input,
                    manifest_charge,
                    intent,
                    intent_readback,
                    destructive_leaf,
                    deletion_progress,
                    retry,
                    moved_out,
                    chain_death,
                    manual,
                    no_more_deletion,
                    optional_backend,
                    broad_prune,
                    parent_fsyncs,
                    settlement,
                )
                self.assertEqual(tuple(sorted(ordered)), ordered)

                for required in (
                    "exact authenticated checkout-parent, Git-admin-parent, and present-root open file descriptions",
                    "same-open-file-description lock lease",
                    "`SCM_RIGHTS`",
                    "reopening any path is successor recovery, not continuity",
                    "not cross-crash custody capabilities",
                    "not an atomic compare-and-unlink",
                    "cooperative same-UID namespace ownership",
                    "every lane-controlled writer is quiescent or excluded",
                    "outside this no-container threat model",
                    "mixed state is manual-recovery-only before deletion",
                    "component-wise relative path and exact raw name bytes",
                    "device/inode/owner/link count",
                    "exact no-follow `readlinkat` byte length and SHA-256",
                    "grouped checkout charge",
                    "1 GiB checkout-accounting cap",
                    "simultaneous temporary and published",
                    "owner-only without replacement",
                    "exact-byte readback",
                    "continuous-custody owner/guardian identity",
                    "exact open-description identities",
                    "initially empty same-live deletion-progress set",
                    "missing entry is acceptable only",
                    "Any injected, replaced, recreated, moved-in, parent/root-replaced",
                    "full grouped checkout charges",
                    "`cleanup-warning`",
                    "`blocked-worktree-capacity`",
                    "path reopen, numeric device/inode equality, or a manifest subset never authorizes",
                    "stable durable handles for both parents, the root, and every descendant",
                    "authoritative deletion-versus-move evidence for every absent entry",
                    "atomic manifest capture or namespace write exclusion",
                    "Unsupported, permission-denied, incomplete, or stale handles fail closed",
                    "already sealed final artifact",
                    "ordinary `.git` marker",
                    "alias registration",
                    "`gitdir` binding",
                    "quarantine rename",
                ):
                    self.assertIn(required, content)
                self.assertNotIn(
                    "Recovery is explicitly idempotent after a crash", content
                )
                self.assertNotIn("resumes from durable manifest intent", content)
                self.assertNotIn("`rm -rf`", content)

    def test_targeted_manifest_is_external_and_reserved_before_use(self) -> None:
        candidates = {
            "pr-readiness": (
                SKILL_ROOT / "references/pr-readiness.md"
            ).read_text(encoding="utf-8"),
            "review-lane-contracts": (
                SKILL_ROOT / "references/review-lane-contracts.md"
            ).read_text(encoding="utf-8"),
        }

        for name, content in candidates.items():
            with self.subTest(contract=name):
                formula = content.index(
                    "`checkout_manifest_entry_bound = 1 + entry_count + unique_parent_directory_count + 3`"
                )
                entry_formula = content.index(
                    "`targeted_manifest_entry_bound = checkout_manifest_entry_bound + 1 + registration_descendant_count_cap`",
                    formula,
                )
                payload_formula = content.index(
                    "`targeted_manifest_payload_bound = targeted_manifest_format_header_bound + tree_metadata_bytes + unique_parent_path_bytes + checkout_synthetic_path_bytes_bound + registration_path_bytes_cap + 192 * targeted_manifest_entry_bound`",
                    entry_formula,
                )
                file_formula = content.index(
                    "`targeted_manifest_file_bound = align_up(targeted_manifest_payload_bound, A_checkout) + A_checkout`",
                    payload_formula,
                )
                simultaneous_formula = content.index(
                    "`targeted_manifest_bound = 2 * targeted_manifest_file_bound + 2 * A_checkout`",
                    file_formula,
                )
                reservation = content.index(
                    "sibling control namespace", simultaneous_formula
                )
                later_use = content.index(
                    "The manifest payload is never embedded in attempt state",
                    reservation,
                )
                intent = content.index(
                    "The intent embeds only the external manifest path, identity, length, and SHA-256—never its payload",
                    later_use,
                )
                cleanup = content.index(
                    "exact-remove the mandatory manifest temporary and published files",
                    intent,
                )
                settlement = content.index(
                    "`checkout_settlement=exact`", cleanup
                )

                self.assertEqual(
                    tuple(
                        sorted(
                            (
                                formula,
                                entry_formula,
                                payload_formula,
                                file_formula,
                                simultaneous_formula,
                                reservation,
                                later_use,
                                intent,
                                cleanup,
                                settlement,
                            )
                        )
                    ),
                    (
                        formula,
                        entry_formula,
                        payload_formula,
                        file_formula,
                        simultaneous_formula,
                        reservation,
                        later_use,
                        intent,
                        cleanup,
                        settlement,
                    ),
                )
                for required in (
                    "fixed-format canonical binary",
                    "Independently aggregate the actual frozen raw paths",
                    "do not infer either",
                    "bounded NUL-delimited frozen-path stream",
                    "authenticated Git tree depth-first order",
                    "strict full raw-path byte ordering",
                    "directory descent compares at the literal `/` byte",
                    "Retain only the previous full raw path",
                    "scalar depth/accounting state and no boundary stack",
                    "Scan the current raw path exactly once, byte by byte",
                    "without a current-boundary collection",
                    "simultaneously validate leading/double/trailing slash, depth",
                    "trailing slash is malformed and fails before parent accounting",
                    "never a component-tuple comparator",
                    "previous/current common raw-byte prefix",
                    "run the complete projector before reading the next byte",
                    "do not read any suffix byte from that same raw record",
                    "Only after the entire record succeeds",
                    "never split or copy component bytes",
                    "Never join or retain all parent prefixes",
                    "never build a parent set/trie",
                    "linear only in the already-capped longest single raw path/depth",
                    "Before requesting the first frozen-path record",
                    "calling the iterable's `__next__`",
                    "`unique_parent_directory_count=0`",
                    "`unique_parent_path_bytes=0`",
                    "`consumed_paths=0`",
                    "never touches the path stream",
                    "same overflow-checked monotone partial projector",
                    "checkout base bound excluding unique-parent directory allocation",
                    "Git-admin bound, `A_checkout`",
                    "complete manifest payload, alignment",
                    "simultaneous temporary-plus-published factor",
                    "`A_checkout * current_unique_parent_directory_count` directory allocation",
                    "per-filesystem grouped physical lower bound",
                    "per-filesystem headroom excess returns the contract status `blocked-worktree-capacity`",
                    "parent-only count/byte/accounting cap may be an additional earlier gate",
                    "never substitutes for this projector",
                    "without consuming the rest of the stream",
                    "require `consumed_paths` to equal the authenticated fixed `entry_count`",
                    "truncated or extra path stream fails closed",
                    "before calling `len`, indexing, or otherwise touching the contents of that extra record",
                    "Gitlinks are already included in `entry_count`",
                    "`3` covers `.git`, `.codex-review`, and `.codex-review/review.diff`",
                    "registration root",
                    "`registration_descendant_count_cap = 16`",
                    "`registration_path_bytes_cap = 4096`",
                    "external sibling control namespace is not a manifest descendant record",
                    "format header, checkout synthetic raw-path allowance, and registration raw-path allowance",
                    "unique_parent_path_bytes` separately supplies synthesized parent paths",
                    "target byte length and SHA-256",
                    "temporary and published",
                    "checkout-root filesystem",
                    "owner-only/no-follow",
                    "existing fixed control-metadata budget",
                    "actual payload/allocation above a bound fails closed",
                    "unique-parent aggregation/path-byte or registration enumeration uncertainty",
                    "Immediately after worktree creation",
                    "before cleanup",
                    "empty sibling control namespace",
                    "absence of all three reservation-bound names",
                ):
                    self.assertIn(required, content)
                self.assertNotIn("If an external form is selected", content)
                self.assertNotIn("The intent embeds the manifest", content)

    def test_targeted_manifest_accounting_model_covers_all_ledgers(self) -> None:
        leaf_accounting = _unique_parent_path_accounting((b"leaf",))
        self.assertEqual("ok", leaf_accounting["status"])
        self.assertEqual(0, leaf_accounting["unique_parent_directory_count"])
        self.assertEqual(0, leaf_accounting["unique_parent_path_bytes"])

        nested_accounting = _unique_parent_path_accounting(
            (b"a/b/leaf", b"a/b/other", b"c/leaf")
        )
        self.assertEqual("ok", nested_accounting["status"])
        self.assertEqual(3, nested_accounting["unique_parent_directory_count"])
        self.assertEqual(
            len(b"a") + len(b"a/b") + len(b"c"),
            nested_accounting["unique_parent_path_bytes"],
        )
        separate_accounting = _unique_parent_path_accounting(
            (b"a/b/leaf", b"a/b/other", b"c/leaf", b"d/leaf")
        )
        self.assertEqual(
            nested_accounting["unique_parent_directory_count"] + 1,
            separate_accounting["unique_parent_directory_count"],
        )
        self.assertEqual(
            nested_accounting["unique_parent_path_bytes"] + len(b"d"),
            separate_accounting["unique_parent_path_bytes"],
        )

        git_order_edge = _unique_parent_path_accounting(
            (b"a.c", b"a/b", b"a0")
        )
        self.assertEqual("ok", git_order_edge["status"])
        self.assertEqual(1, git_order_edge["unique_parent_directory_count"])
        self.assertEqual(len(b"a"), git_order_edge["unique_parent_path_bytes"])
        wrong_raw_order = _unique_parent_path_accounting((b"a/b", b"a.c"))
        self.assertEqual("fail-closed-path-order", wrong_raw_order["status"])

        deep_parent_count = 20_000
        deep_path = b"x/" * deep_parent_count + b"leaf"
        deep_accounting = _unique_parent_path_accounting((deep_path,))
        self.assertEqual("ok", deep_accounting["status"])
        self.assertEqual(
            deep_parent_count,
            deep_accounting["unique_parent_directory_count"],
        )
        self.assertEqual(
            deep_parent_count * deep_parent_count,
            deep_accounting["unique_parent_path_bytes"],
        )
        self.assertLessEqual(
            deep_accounting["peak_retained_raw_bytes"],
            2 * len(deep_path),
        )
        self.assertLessEqual(
            deep_accounting["peak_parent_depth"],
            deep_parent_count,
        )

        depth_limited = _unique_parent_path_accounting(
            (b"x/" * 10_000 + b"leaf",),
            max_depth=4,
        )
        self.assertEqual("fail-closed-path-bound", depth_limited["status"])
        self.assertEqual(3, depth_limited["retained_parent_depth"])
        self.assertLessEqual(depth_limited["scanned_raw_bytes"], 2 * 4)

        trailing_slash = _unique_parent_path_accounting(
            (b"a/",),
            parent_count_cap=0,
        )
        self.assertEqual("fail-closed-path-bound", trailing_slash["status"])
        self.assertEqual(2, trailing_slash["scanned_raw_bytes"])

        def fail_if_consumed_after_bound() -> Iterable[bytes]:
            yield b"a/b/leaf"
            raise AssertionError("aggregator consumed after known bound failure")

        early_failure = _unique_parent_path_accounting(
            fail_if_consumed_after_bound(),
            parent_accounting_cap=100,
        )
        self.assertEqual(
            "fail-closed-parent-accounting-bound",
            early_failure["status"],
        )
        self.assertEqual(1, early_failure["consumed_paths"])

        a_checkout = 4096
        entry_count = 100_000
        parent_accounting = _unique_parent_path_accounting(
            f"parent-{index:05d}/leaf".encode("ascii")
            for index in range(entry_count)
        )
        self.assertEqual("ok", parent_accounting["status"])
        unique_parent_directory_count = parent_accounting[
            "unique_parent_directory_count"
        ]
        unique_parent_path_bytes = parent_accounting["unique_parent_path_bytes"]
        self.assertEqual(100_000, entry_count)
        self.assertEqual(100_000, unique_parent_directory_count)
        self.assertEqual(
            sum(len(f"parent-{index:05d}".encode("ascii")) for index in range(100_000)),
            unique_parent_path_bytes,
        )

        tree_metadata_bytes = 128 * 1024 * 1024
        checkout_base_bound_without_parents = 128 * 1024 * 1024
        git_admin_bound = 64 * 1024 * 1024
        process_envelope = 257 * 1024 * 1024
        model_inputs = {
            "entry_count": entry_count,
            "tree_metadata_bytes": tree_metadata_bytes,
            "unique_parent_directory_count": unique_parent_directory_count,
            "unique_parent_path_bytes": unique_parent_path_bytes,
            "registration_descendant_count": 16,
            "registration_path_bytes": 4096,
            "a_checkout": a_checkout,
            "checkout_base_bound_without_parents": (
                checkout_base_bound_without_parents
            ),
            "git_admin_bound": git_admin_bound,
        }
        result = _targeted_manifest_accounting_model(
            **model_inputs,
            checkout_filesystem="checkout-fs",
            manifest_filesystem="checkout-fs",
            git_filesystem="git-fs",
            retention_filesystem="retention-fs",
        )

        checkout_entry_bound = (
            1 + entry_count + unique_parent_directory_count + 3
        )
        entry_bound = checkout_entry_bound + 1 + 16
        payload_bound = (
            4096
            + tree_metadata_bytes
            + unique_parent_path_bytes
            + 4096
            + 4096
            + 192 * entry_bound
        )
        aligned_payload = (
            (payload_bound + a_checkout - 1) // a_checkout
        ) * a_checkout
        file_bound = aligned_payload + a_checkout
        targeted_bound = 2 * file_bound + 2 * a_checkout
        checkout_parent_allocation_bound = (
            a_checkout * unique_parent_directory_count
        )
        checkout_root_bound = (
            checkout_base_bound_without_parents
            + checkout_parent_allocation_bound
            + targeted_bound
        )
        checkout_accounting_bound = checkout_root_bound + git_admin_bound

        self.assertEqual("admitted", result["status"])
        self.assertEqual(
            unique_parent_directory_count,
            result["unique_parent_directory_count"],
        )
        self.assertEqual(
            unique_parent_path_bytes,
            result["unique_parent_path_bytes"],
        )
        self.assertEqual(
            checkout_entry_bound,
            result["checkout_manifest_entry_bound"],
        )
        self.assertEqual(16, result["registration_descendant_count_cap"])
        self.assertEqual(4096, result["registration_path_bytes_cap"])
        self.assertEqual(entry_bound, result["targeted_manifest_entry_bound"])
        self.assertEqual(payload_bound, result["targeted_manifest_payload_bound"])
        self.assertEqual(file_bound, result["targeted_manifest_file_bound"])
        self.assertEqual(2 * a_checkout, result["targeted_manifest_control_bound"])
        self.assertEqual(targeted_bound, result["targeted_manifest_bound"])
        self.assertEqual(
            checkout_parent_allocation_bound,
            result["checkout_parent_allocation_bound"],
        )
        self.assertEqual(
            2 * file_bound,
            result["targeted_manifest_bound"]
            - result["targeted_manifest_control_bound"],
        )
        self.assertEqual(checkout_root_bound, result["checkout_root_bound"])
        self.assertEqual(
            checkout_accounting_bound,
            result["checkout_accounting_bound"],
        )
        self.assertEqual("checkout", result["targeted_manifest_ledger"])
        self.assertEqual("checkout-fs", result["targeted_manifest_filesystem"])
        self.assertEqual(
            {
                "process": process_envelope,
                "checkout": checkout_accounting_bound,
            },
            result["logical_ledgers"],
        )
        self.assertEqual(
            {
                "retention-fs": process_envelope,
                "checkout-fs": checkout_root_bound,
                "git-fs": git_admin_bound,
            },
            result["physical_projection"],
        )

        class GuardedByteRecord(Sequence[int]):
            def __init__(self, data: bytes, allowed_last_index: int) -> None:
                self.data = data
                self.allowed_last_index = allowed_last_index
                self.maximum_accessed_index = -1

            def __len__(self) -> int:
                return len(self.data)

            def __getitem__(self, index: int) -> int:
                if index > self.allowed_last_index:
                    raise AssertionError("scanner read guarded raw-path suffix")
                if index < 0 or index >= len(self.data):
                    raise IndexError
                self.maximum_accessed_index = max(
                    self.maximum_accessed_index,
                    index,
                )
                return self.data[index]

        projector_path = b"a/bb/ccc/" + b"tail/" * 10_000 + b"leaf"
        kth_parent_count = 3
        kth_slash_index = len(b"a/bb/ccc")
        prior_parent_path_bytes = len(b"a") + len(b"a/bb")
        kth_parent_path_bytes = prior_parent_path_bytes + len(b"a/bb/ccc")
        projector_fixed_inputs: dict[str, object] = {
            "entry_count": 1,
            "tree_metadata_bytes": len(projector_path),
            "registration_descendant_count": 16,
            "registration_path_bytes": 4096,
            "a_checkout": a_checkout,
            "checkout_base_bound_without_parents": (
                checkout_base_bound_without_parents
            ),
            "git_admin_bound": git_admin_bound,
            "checkout_filesystem": "checkout-fs",
            "manifest_filesystem": "checkout-fs",
            "git_filesystem": "git-fs",
            "retention_filesystem": "retention-fs",
        }

        class NeverYield(Iterable[Sequence[int]]):
            def __init__(self) -> None:
                self.next_requested = False

            def __iter__(self) -> NeverYield:
                return self

            def __next__(self) -> Sequence[int]:
                self.next_requested = True
                raise AssertionError("baseline failure requested the first path")

        baseline_projection = _targeted_manifest_accounting_model(
            unique_parent_directory_count=0,
            unique_parent_path_bytes=0,
            **projector_fixed_inputs,
        )
        self.assertEqual("admitted", baseline_projection["status"])
        checkout_never_yield = NeverYield()
        baseline_checkout_failure = _unique_parent_path_accounting(
            checkout_never_yield,
            projection_inputs={
                **projector_fixed_inputs,
                "checkout_cap": baseline_projection[
                    "checkout_accounting_bound"
                ] - 1,
            },
        )
        self.assertEqual(
            "blocked-worktree-capacity",
            baseline_checkout_failure["status"],
        )
        self.assertEqual(0, baseline_checkout_failure["consumed_paths"])
        self.assertFalse(checkout_never_yield.next_requested)

        root_only = _unique_parent_path_accounting(
            (b"leaf",),
            projection_inputs=projector_fixed_inputs,
        )
        self.assertEqual("ok", root_only["status"])
        truncated = _unique_parent_path_accounting(
            (),
            projection_inputs=projector_fixed_inputs,
        )
        self.assertEqual("fail-closed-entry-count-mismatch", truncated["status"])
        class UntouchableExtraRecord(Sequence[int]):
            def __init__(self) -> None:
                self.length_requested = False
                self.item_requested = False

            def __len__(self) -> int:
                self.length_requested = True
                raise AssertionError("scanner requested extra-record length")

            def __getitem__(self, index: int) -> int:
                self.item_requested = True
                raise AssertionError("scanner indexed extra-record contents")

        class OnePlusExtra(Iterable[Sequence[int]]):
            def __init__(self, extra_record: Sequence[int]) -> None:
                self.extra_record = extra_record
                self.next_requests = 0

            def __iter__(self) -> OnePlusExtra:
                return self

            def __next__(self) -> Sequence[int]:
                self.next_requests += 1
                if self.next_requests == 1:
                    return b"a"
                if self.next_requests == 2:
                    return self.extra_record
                raise AssertionError("scanner requested a record after excess")

        extra_record = UntouchableExtraRecord()
        extra_stream = OnePlusExtra(extra_record)
        extra = _unique_parent_path_accounting(
            extra_stream,
            projection_inputs=projector_fixed_inputs,
        )
        self.assertEqual("fail-closed-entry-count-mismatch", extra["status"])
        self.assertEqual(2, extra["consumed_paths"])
        self.assertEqual(2, extra_stream.next_requests)
        self.assertFalse(extra_record.length_requested)
        self.assertFalse(extra_record.item_requested)

        prior_parent_projection = _targeted_manifest_accounting_model(
            unique_parent_directory_count=kth_parent_count - 1,
            unique_parent_path_bytes=prior_parent_path_bytes,
            **projector_fixed_inputs,
        )
        self.assertEqual("admitted", prior_parent_projection["status"])
        kth_parent_projection = _targeted_manifest_accounting_model(
            unique_parent_directory_count=kth_parent_count,
            unique_parent_path_bytes=kth_parent_path_bytes,
            **projector_fixed_inputs,
        )
        self.assertGreater(
            kth_parent_projection["checkout_accounting_bound"],
            prior_parent_projection["checkout_accounting_bound"],
        )

        checkout_guard = GuardedByteRecord(projector_path, kth_slash_index)

        def fail_after_checkout_cap() -> Iterable[Sequence[int]]:
            yield checkout_guard
            raise AssertionError("checkout-cap projector consumed a second path")

        checkout_cap_failure = _unique_parent_path_accounting(
            fail_after_checkout_cap(),
            projection_inputs={
                **projector_fixed_inputs,
                "checkout_cap": prior_parent_projection[
                    "checkout_accounting_bound"
                ],
            },
        )
        self.assertEqual(
            "blocked-worktree-capacity", checkout_cap_failure["status"]
        )
        self.assertEqual(1, checkout_cap_failure["consumed_paths"])
        self.assertEqual(kth_slash_index, checkout_guard.maximum_accessed_index)
        self.assertEqual(
            kth_slash_index + 1,
            checkout_cap_failure["scanned_raw_bytes"],
        )
        self.assertEqual(
            kth_parent_count,
            checkout_cap_failure["unique_parent_directory_count"],
        )

        shared_fixed_inputs = {
            **projector_fixed_inputs,
            "checkout_filesystem": "shared-fs",
            "manifest_filesystem": "shared-fs",
            "git_filesystem": "shared-fs",
            "retention_filesystem": "shared-fs",
        }
        shared_baseline = _targeted_manifest_accounting_model(
            unique_parent_directory_count=0,
            unique_parent_path_bytes=0,
            **shared_fixed_inputs,
        )
        shared_baseline_charge = shared_baseline["physical_projection"]["shared-fs"]
        shared_never_yield = NeverYield()
        baseline_shared_failure = _unique_parent_path_accounting(
            shared_never_yield,
            projection_inputs={
                **shared_fixed_inputs,
                "filesystem_headroom": {
                    "shared-fs": shared_baseline_charge - 1,
                },
            },
        )
        self.assertEqual(
            "blocked-worktree-capacity",
            baseline_shared_failure["status"],
        )
        self.assertEqual(0, baseline_shared_failure["consumed_paths"])
        self.assertFalse(shared_never_yield.next_requested)

        shared_prior_parent = _targeted_manifest_accounting_model(
            unique_parent_directory_count=kth_parent_count - 1,
            unique_parent_path_bytes=prior_parent_path_bytes,
            **shared_fixed_inputs,
        )
        shared_prior_charge = shared_prior_parent["physical_projection"]["shared-fs"]

        shared_guard = GuardedByteRecord(projector_path, kth_slash_index)

        def fail_after_shared_headroom() -> Iterable[Sequence[int]]:
            yield shared_guard
            raise AssertionError("headroom projector consumed a second path")

        shared_headroom_failure = _unique_parent_path_accounting(
            fail_after_shared_headroom(),
            projection_inputs={
                **shared_fixed_inputs,
                "filesystem_headroom": {"shared-fs": shared_prior_charge},
            },
        )
        self.assertEqual(
            "blocked-worktree-capacity", shared_headroom_failure["status"]
        )
        self.assertEqual(1, shared_headroom_failure["consumed_paths"])
        self.assertEqual(kth_slash_index, shared_guard.maximum_accessed_index)
        self.assertEqual(
            kth_slash_index + 1,
            shared_headroom_failure["scanned_raw_bytes"],
        )
        self.assertEqual(
            kth_parent_count,
            shared_headroom_failure["unique_parent_directory_count"],
        )

        shared = _targeted_manifest_accounting_model(
            **model_inputs,
            checkout_filesystem="shared-fs",
            manifest_filesystem="shared-fs",
            git_filesystem="shared-fs",
            retention_filesystem="shared-fs",
        )
        self.assertEqual(
            process_envelope + checkout_accounting_bound,
            shared["physical_projection"]["shared-fs"],
        )

        blocked = _targeted_manifest_accounting_model(
            **{
                **model_inputs,
                "checkout_base_bound_without_parents": 1024 * 1024 * 1024,
            },
            checkout_filesystem="checkout-fs",
            manifest_filesystem="checkout-fs",
            git_filesystem="git-fs",
            retention_filesystem="retention-fs",
        )
        self.assertEqual("blocked-worktree-capacity", blocked["status"])
        self.assertEqual(
            1024 * 1024 * 1024
            + checkout_parent_allocation_bound
            + targeted_bound,
            blocked["physical_projection"]["checkout-fs"],
        )

        mismatch = _targeted_manifest_accounting_model(
            entry_count=1,
            tree_metadata_bytes=1,
            unique_parent_directory_count=0,
            unique_parent_path_bytes=0,
            registration_descendant_count=0,
            registration_path_bytes=0,
            a_checkout=a_checkout,
            checkout_base_bound_without_parents=1,
            git_admin_bound=1,
            checkout_filesystem="checkout-fs",
            manifest_filesystem="retention-fs",
            git_filesystem="git-fs",
            retention_filesystem="retention-fs",
        )
        self.assertEqual(
            "fail-closed-cross-filesystem-mismatch", mismatch["status"]
        )

        for name, override in {
            "registration-count": {"registration_descendant_count": 17},
            "registration-path-bytes": {"registration_path_bytes": 4097},
        }.items():
            with self.subTest(registration_bound=name):
                registration_exceeded = _targeted_manifest_accounting_model(
                    **{**model_inputs, **override},
                    checkout_filesystem="checkout-fs",
                    manifest_filesystem="checkout-fs",
                    git_filesystem="git-fs",
                    retention_filesystem="retention-fs",
                )
                self.assertEqual(
                    "fail-closed-registration-bound-exceeded",
                    registration_exceeded["status"],
                )

        for name, override in {
            "unique-parent-count": {
                "entry_count": 0,
                "unique_parent_directory_count": (1 << 63) - 1,
            },
            "unique-parent-path-bytes": {
                "entry_count": 0,
                "unique_parent_path_bytes": (1 << 63) - 1,
            },
        }.items():
            with self.subTest(overflow=name):
                overflow_inputs = {
                    **model_inputs,
                    "tree_metadata_bytes": 0,
                    "unique_parent_directory_count": 0,
                    "unique_parent_path_bytes": 0,
                    "checkout_base_bound_without_parents": 0,
                    "git_admin_bound": 0,
                    **override,
                }
                overflow = _targeted_manifest_accounting_model(
                    **overflow_inputs,
                    checkout_filesystem="checkout-fs",
                    manifest_filesystem="checkout-fs",
                    git_filesystem="git-fs",
                    retention_filesystem="retention-fs",
                )
                self.assertEqual("fail-closed-overflow", overflow["status"])

        grouped_projection_overflow = _targeted_manifest_accounting_model(
            entry_count=1,
            tree_metadata_bytes=0,
            unique_parent_directory_count=0,
            unique_parent_path_bytes=0,
            registration_descendant_count=0,
            registration_path_bytes=0,
            a_checkout=a_checkout,
            checkout_base_bound_without_parents=10_000,
            git_admin_bound=10_000,
            checkout_filesystem="shared-fs",
            manifest_filesystem="shared-fs",
            git_filesystem="shared-fs",
            retention_filesystem="shared-fs",
            process_envelope=50_000,
            checkout_cap=100_000,
            max_integer=100_000,
        )
        self.assertEqual(
            "fail-closed-overflow", grouped_projection_overflow["status"]
        )

        exceeded = _targeted_manifest_accounting_model(
            **model_inputs,
            checkout_filesystem="checkout-fs",
            manifest_filesystem="checkout-fs",
            git_filesystem="git-fs",
            retention_filesystem="retention-fs",
            actual_payload_bytes=payload_bound + 1,
        )
        self.assertEqual("fail-closed-bound-exceeded", exceeded["status"])

        published_allocation_exceeded = _targeted_manifest_accounting_model(
            **model_inputs,
            checkout_filesystem="checkout-fs",
            manifest_filesystem="checkout-fs",
            git_filesystem="git-fs",
            retention_filesystem="retention-fs",
            actual_temp_allocation=file_bound,
            actual_published_allocation=file_bound + 1,
        )
        self.assertEqual(
            "fail-closed-bound-exceeded",
            published_allocation_exceeded["status"],
        )
    def test_targeted_cleanup_resume_requires_live_custody_or_strict_backend(
        self,
    ) -> None:
        manifest = {
            b"": ("directory", 7, 100, 501, 1, "root-generation-1"),
            b".git": ("file", 7, 101, 501, 1, "git-generation-1"),
            b"nested": ("directory", 7, 102, 501, 1, "dir-generation-1"),
            b"nested/file": ("file", 7, 103, 501, 1, "file-generation-1"),
        }
        after_git_leaf_deleted = {
            path: identity
            for path, identity in manifest.items()
            if path != b".git"
        }
        live_kwargs = {
            "continuous_live_custody": True,
            "deleted_by_live_chain": frozenset({b".git"}),
        }
        self.assertEqual(
            (
                "resume-live-custody",
                "charged-until-exact-settlement",
                True,
            ),
            _targeted_cleanup_resume_model(
                manifest,
                after_git_leaf_deleted,
                **live_kwargs,
            ),
        )
        self.assertEqual(
            (
                "double-absence-barrier",
                "charged-until-exact-settlement",
                True,
            ),
            _targeted_cleanup_resume_model(
                manifest,
                {},
                continuous_live_custody=True,
                deleted_by_live_chain=frozenset(manifest),
            ),
        )

        manual = (
            "manual-recovery-required",
            "full-grouped-charges-retained",
            True,
        )
        successor_cases = {
            "chain-died-after-marker-delete": {
                "continuous_live_custody": False,
            },
            "path-reopened": {
                "continuous_live_custody": True,
                "path_reopened": True,
            },
            "same-numeric-devino-is-not-authority": {
                "continuous_live_custody": False,
                "exact_open_descriptions": True,
            },
            "lost-same-ofd-lock": {
                "continuous_live_custody": True,
                "same_ofd_lock": False,
            },
            "lane-writer-not-quiescent": {
                "continuous_live_custody": True,
                "namespace_write_excluded": False,
            },
            "parent-aba": {
                "continuous_live_custody": True,
                "parent_identity_matches": False,
            },
        }
        for name, kwargs in successor_cases.items():
            with self.subTest(recovery=name):
                self.assertEqual(
                    manual,
                    _targeted_cleanup_resume_model(
                        manifest,
                        after_git_leaf_deleted,
                        deleted_by_live_chain=frozenset({b".git"}),
                        **kwargs,
                    ),
                )

        moved_out_subset = {
            path: identity
            for path, identity in after_git_leaf_deleted.items()
            if path != b"nested/file"
        }
        self.assertEqual(
            manual,
            _targeted_cleanup_resume_model(
                manifest,
                moved_out_subset,
                **live_kwargs,
            ),
        )

        injected = dict(after_git_leaf_deleted)
        injected[b"new"] = ("file", 7, 104, 501, 1, "new-generation-1")
        replaced = dict(after_git_leaf_deleted)
        replaced[b"nested/file"] = (
            "file",
            7,
            204,
            501,
            1,
            "replacement-generation-1",
        )
        root_aba = dict(after_git_leaf_deleted)
        root_aba[b""] = (
            "directory",
            7,
            100,
            501,
            1,
            "root-generation-2",
        )
        for name, observed in {
            "injected": injected,
            "replaced": replaced,
            "root-aba": root_aba,
        }.items():
            with self.subTest(recovery=name):
                self.assertEqual(
                    manual,
                    _targeted_cleanup_resume_model(
                        manifest,
                        observed,
                        **live_kwargs,
                    ),
                )

        for name, override in {
            "missing-side-reappeared": {"missing_side_absent": False},
            "alias-reappeared": {"alias_absent": False},
        }.items():
            with self.subTest(recovery=name):
                self.assertEqual(
                    manual,
                    _targeted_cleanup_resume_model(
                        manifest,
                        after_git_leaf_deleted,
                        **live_kwargs,
                        **override,
                    ),
                )

        self.assertEqual(
            manual,
            _targeted_cleanup_resume_model(
                manifest,
                after_git_leaf_deleted,
                continuous_live_custody=False,
                cross_crash_backend_opted_in=True,
                backend_stable_handles_for_all=True,
                backend_absence_proof=False,
                backend_atomic_capture_or_exclusion=True,
            ),
        )
        self.assertEqual(
            (
                "resume-opt-in-backend",
                "charged-until-exact-settlement",
                True,
            ),
            _targeted_cleanup_resume_model(
                manifest,
                after_git_leaf_deleted,
                continuous_live_custody=False,
                cross_crash_backend_opted_in=True,
                backend_stable_handles_for_all=True,
                backend_absence_proof=True,
                backend_atomic_capture_or_exclusion=True,
            ),
        )
    def test_independent_codex_trust_profile_is_isolated_and_verified(
        self,
    ) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        readme = (tool_root / "README.md").read_text(encoding="utf-8")
        protocol = (tool_root / "review_supervisor/appserver_protocol.py").read_text(
            encoding="utf-8"
        )
        constants = (tool_root / "review_supervisor/constants.py").read_text(
            encoding="utf-8"
        )
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for value in (readme, readiness, contracts):
            self.assertIn("app-server", value)
            self.assertIn("CODEX_HOME", value)
            self.assertIn("gpt-5.6-sol", value)
            self.assertIn("xhigh", value)
        self.assertIn("--strict-config", readme)
        self.assertIn("Do not use tools", constants)
        self.assertIn('"sessionFlags"', protocol)
        self.assertIn('"config/read"', protocol)
        self.assertIn("isolated", readiness.lower())
        self.assertIn("sealed", contracts.lower())
        self.assertNotIn("codex exec --ephemeral", skill)
        self.assertNotIn("codex exec --ephemeral", readiness)
        self.assertNotIn("codex exec --ephemeral", contracts)

        for removed in (
            "references/independent-codex-runtime-policy.json",
            "scripts/review_runtime/independent_codex.py",
            "tests/test_independent_codex.py",
        ):
            self.assertFalse((SKILL_ROOT / removed).exists())

    def test_independent_diff_is_sealed_into_raw_checkout(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("with `--keep-workspace`", readiness)
        for name in ("`preflight.json`", "`control-artifact-state.json`", "`review.diff`"):
            self.assertIn(name, readiness)
        self.assertIn("control-state SHA-256", readiness)
        self.assertIn("byte length, and SHA-256 exactly match", readiness)
        self.assertIn("scanned `primary_diff` attestation", readiness)
        self.assertIn("relative path", readiness)
        self.assertIn("reject a diff larger than 128 MiB", readiness)
        self.assertIn(
            "do not substitute it for the `primary_diff` attestation", readiness
        )
        self.assertIn("Do not intentionally request cleanup earlier", readiness)

        self.assertIn("helper attempt/state identity", contracts)
        self.assertIn("exact frozen `base_sha..head_sha`", contracts)
        self.assertIn("source device/inode/owner/type/link count", contracts)
        self.assertIn("SHA-256 of the current durable control-artifact state", contracts)
        self.assertIn("do not represent that control-state digest as part of the preflight attestation", contracts)
        self.assertIn("including the 128 MiB maximum", contracts)
        self.assertIn("destination `.codex-review/review.diff`", contracts)
        self.assertIn("helper-owned synthetic control artifact rather than a PR change", contracts)
        self.assertIn("complete primary diff", contracts)

        for value in (readiness, contracts):
            self.assertIn("`.codex-review/review.diff`", value)
            self.assertIn("no-follow", value)
            self.assertIn("owner", value)
            self.assertIn("exact readback", value)
        self.assertIn("already-open no-follow source descriptor", readiness)
        self.assertIn("shared BSD `flock` lease", readiness)
        self.assertIn("shared helper-cleanup lease", contracts)
        self.assertIn("bounded metadata-eligibility result", contracts)
        self.assertIn("must not synchronously hash the potentially 128 MiB primary diff", contracts)
        self.assertIn("supervise a complete streaming SHA-256 check", contracts)

        for value in (readiness, contracts):
            self.assertIn("`cleanup.lock`", value)
            self.assertIn("exclusive lock", value)
            self.assertIn("10-minute checkout deadline", value)
            self.assertIn("`SCM_RIGHTS`", value)
        self.assertIn("never reopen its pathname", readiness)
        self.assertIn("do not reopen its pathname", contracts)
        self.assertIn("cannot unlink the workspace", readiness)
        self.assertIn("attempted concurrent cleanup instead waits or times out", readiness)
        self.assertIn("Do not fully read or hash", readiness)
        self.assertIn("not an unbounded pre-admission read", contracts)
        self.assertIn("potentially 128 MiB streaming digest/copy only inside", contracts)
        self.assertIn("source descriptor and shared helper-cleanup lease", contracts)

    def test_independent_diff_charge_is_in_checkout_ledger(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "review_diff_bound = align_up(review_diff_length, checkout_allocation_unit) + 2 * checkout_allocation_unit",
            readiness,
        )
        self.assertIn("grouped checkout charges including `review_diff_bound`", readiness)
        self.assertIn("belongs to the checkout ledger", readiness)
        self.assertIn("never the 257 MiB process envelope", readiness)

        self.assertIn(
            "`review_diff_bound = align_up(review_diff_length, A_checkout) + 2 * A_checkout`",
            contracts,
        )
        self.assertIn("add it to `checkout_root_bound`", contracts)
        self.assertIn("include it in `checkout_accounting_bound`", contracts)
        self.assertIn("checkout-root physical projection", contracts)
        self.assertIn("1 GiB logical cap", contracts)
        self.assertIn("reservation, settlement, and retained-worktree charge", contracts)
        self.assertIn("not part of the 257 MiB process-artifact envelope", contracts)

    def test_independent_control_namespace_preserves_no_extra_integrity(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("base/head manifest or staging alias", readiness)
        self.assertIn("top-level synthetic `.codex-review` namespace", readiness)
        self.assertIn("validate the complete base/head symlink graph", readiness)
        self.assertIn("`.codex-review` directory with mode `0700`", readiness)
        self.assertIn("`.codex-review/review.diff` placeholder with mode `0600`", readiness)
        self.assertIn("Do not use `cp`, hard links, reflinks, symlinks, or path replacement", readiness)
        self.assertIn("`fsync`, `fstat`, close, reopen no-follow", readiness)
        self.assertIn("bounded frozen-index `filter` / `working-tree-encoding` query", readiness)
        self.assertIn("`git ls-files` to equal the exact head manifest", readiness)
        self.assertIn("two-entry synthetic control manifest", readiness)
        self.assertIn("no staging or other extra path", readiness)

        self.assertIn("synthetic `.codex-review` namespace", contracts)
        self.assertIn("frozen base and head trees", contracts)
        self.assertIn("no tracked symlink graph may resolve into `.codex-review`", contracts)
        self.assertIn("one real `.codex-review` directory created mode `0700`", contracts)
        self.assertIn("one empty `review.diff` regular placeholder created mode `0600`", contracts)
        self.assertIn("Do not use `cp`", contracts)
        self.assertIn("a hard link, clone/reflink, symlink", contracts)
        self.assertIn("any path-replacing write", contracts)
        self.assertIn("same bounded sanitized frozen-index attribute query", contracts)
        self.assertIn("no staged synthetic entry", contracts)
        self.assertIn("absence of staging names or any other entry", contracts)

    def test_independent_reviewer_keeps_read_only_input_boundary(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        readme = (tool_root / "README.md").read_text(encoding="utf-8")
        constants = (tool_root / "review_supervisor/constants.py").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for value in (readiness, contracts):
            self.assertIn("app-server", value)
            self.assertIn("bounded evidence", value)
            self.assertIn("no-execution", value)
            self.assertNotIn("codex exec --ephemeral", value)
        self.assertIn("Do not use tools", constants)
        self.assertIn("filesystem capability", readme)
        self.assertIn("never give the reviewer a checkout path", readiness)

    def test_final_artifact_is_durable_before_terminal_review_state(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        secureio = (tool_root / "review_supervisor/secureio.py").read_text(
            encoding="utf-8"
        )
        runtime = (tool_root / "review_supervisor/runtime.py").read_text(
            encoding="utf-8"
        )
        supervisor = (tool_root / "review_supervisor/supervisor.py").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for operation in (
            "os.fsync(temp_fd)",
            "rename_noreplace(parent_fd, temp_name, parent_fd, name)",
            "os.fsync(parent_fd)",
            "os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW",
            "if written_identity != read_identity",
            "if actual != data",
        ):
            self.assertIn(operation, secureio)

        final_publish = runtime.index(
            "final_identity = publish_bytes(final_path, final_bytes, mode=0o600)"
        )
        pending = runtime.index('"phase": "terminal-authorization-pending"', final_publish)
        authorization = runtime.index(
            "state, state_digest = authorize_terminal_via_helper(", pending
        )
        reviewed = runtime.index('"phase": "reviewed"', authorization)
        self.assertLess(final_publish, pending)
        self.assertLess(pending, authorization)
        self.assertLess(authorization, reviewed)

        for operation in (
            "_verify_final_seal(final_path, requested_seal)",
            '"predecessor_sha256": digest',
            '"readback": "exact-nofollow-under-publication-lease"',
            "terminal_commit_authorized=True",
        ):
            self.assertIn(operation, runtime)
        self.assertIn('"predecessor_sha256": state_digest', supervisor)
        self.assertIn('request_type="final-authorization-commit"', supervisor)
        self.assertIn("_has_exact_final_authorization(", supervisor)
        self.assertIn("final device/inode/length/SHA-256", contracts)
        self.assertIn("predecessor", contracts)
        self.assertIn("final-seal", contracts)

    def test_final_artifact_uses_inclusive_65536_byte_limit(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        constants = (tool_root / "review_supervisor/constants.py").read_text(
            encoding="utf-8"
        )
        final_transport = (tool_root / "review_supervisor/final_transport.py").read_text(
            encoding="utf-8"
        )
        protocol = (tool_root / "review_supervisor/appserver_protocol.py").read_text(
            encoding="utf-8"
        )
        prompt = (tool_root / "review_supervisor/prompt.py").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("FINAL_MESSAGE_BYTES = 65_536", constants)
        self.assertIn("remaining = FINAL_MESSAGE_BYTES", final_transport)
        self.assertIn("overflow = os.read(fifo_fd, 1)", final_transport)
        self.assertIn(
            'if len(text.encode("utf-8", "strict")) > FINAL_MESSAGE_BYTES:',
            protocol,
        )
        self.assertIn("if not 1 <= len(value) <= FINAL_MESSAGE_BYTES:", prompt)
        for phrase in (
            "remaining budget",
            "one-byte overflow probe",
            "1..65,536",
            "65,535",
            "65,537",
        ):
            self.assertIn(phrase, contracts)

        cases = {
            "65535-eof": (
                (b"a" * 32_000, b"b" * 33_535),
                True,
                ("seal-eligible", 65_535, "not-needed"),
            ),
            "65536-eof": (
                (b"a" * 65_535, b"b"),
                True,
                ("seal-eligible", 65_536, "eof"),
            ),
            "65536-still-open": (
                (b"a" * 65_536,),
                False,
                ("incomplete/inconclusive", 65_536, "open"),
            ),
            "65537-overflow": (
                (b"a" * 65_536, b"b"),
                True,
                ("limit-terminated/inconclusive", 65_536, "byte"),
            ),
        }
        for name, (chunks, eof, expected) in cases.items():
            with self.subTest(reader=name):
                self.assertEqual(
                    expected,
                    _bounded_final_reader_model(chunks, eof=eof),
                )

    def test_attempt_supervisor_closes_reader_and_reviewer_after_outer_death(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        runtime = (tool_root / "review_supervisor/runtime.py").read_text(
            encoding="utf-8"
        )
        direct_gate = (tool_root / "review_supervisor/direct_gate.py").read_text(
            encoding="utf-8"
        )
        review_execution = (
            tool_root / "review_supervisor/review_execution.py"
        ).read_text(encoding="utf-8")
        direct_gate_tests = (tool_root / "tests/test_direct_gate.py").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for value in (readiness, contracts):
            self.assertIn("attempt supervisor", value)
            self.assertIn("outer-liveness", value)
            self.assertIn("app-server stdio", value)

        attempt_main = runtime.index("def attempt_supervisor_main(")
        handoff_complete = runtime.index('"handoff": "complete"', attempt_main)
        ownership = runtime.index(
            '"process_owner": "attempt-supervisor"', handoff_complete
        )
        checkout = runtime.index(
            "state, state_digest = _run_checkout(", ownership
        )
        reviewer = runtime.index(
            "state, state_digest, final_text = run_reviewer(", checkout
        )
        self.assertLess(handoff_complete, ownership)
        self.assertLess(ownership, checkout)
        self.assertLess(checkout, reviewer)

        for invariant in (
            'raise OuterAbandoned("outer liveness peer closed")',
            "liveness_checkpoint=lambda: _require_outer_liveness(outer)",
            "abandoned = True",
            "state, state_digest = _record_failure(",
            "abandoned=abandoned",
        ):
            self.assertIn(invariant, runtime)
        for invariant in (
            "if launched is not None and not process_state.leader_reaped:",
            "process_state.exit_code = _terminate_process(",
            "process_state.process_group_empty = True",
            "process_state.pipes_closed = True",
        ):
            self.assertIn(invariant, direct_gate)
        for invariant in (
            "receipt.leader_reaped is not True",
            "receipt.process_group_empty is not True",
            "receipt.stdio_closed is not True",
        ):
            self.assertIn(invariant, review_execution)
        self.assertIn(
            "def test_liveness_checkpoint_aborts_and_reaps_the_launched_process",
            direct_gate_tests,
        )
        self.assertNotIn("codex exec --ephemeral", contracts)

    def test_process_and_checkout_share_physical_free_space_projection(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "add the proposed 257 MiB process-artifact envelope to the retention-root identity",
            contracts,
        )
        self.assertIn("map the process envelope to the retention-root identity", readiness)
        self.assertIn("Charges from all three roles are combined", contracts)
        self.assertIn(
            "same identity receives one floor check after combining process, checkout-root, and Git-admin",
            readiness,
        )
        self.assertIn("retention root on a different filesystem", contracts)
        self.assertIn("different retention-root filesystem receives its own floor check", readiness)
        self.assertIn("without merging their logical ledgers", contracts)
        self.assertIn("subtract verified blocks already allocated", contracts)
        self.assertIn("logical 1 GiB checkout-accounting cap", contracts)
        self.assertIn("per-identity physical-headroom projections", contracts)
        self.assertIn("all three filesystem identities and projections", readiness)
        self.assertIn("retention-root process-only free-space projection", contracts)
        self.assertIn("proved shortfall as `blocked-retention`", contracts)
        self.assertIn("newly introduced physical shortfall as `blocked-worktree-capacity`", contracts)
        self.assertIn(
            "measurement uncertainty at the applicable step is `inconclusive`",
            contracts,
        )
        self.assertIn("retention-root, checkout-root, and common-Git-directory filesystem identities", contracts)
        self.assertIn("filesystem identities and allocation units", contracts)
        self.assertIn("attributed allocated blocks", contracts)
        self.assertIn("first reject any durable `retained-worktree` record", contracts)
        retained_gate = contracts.index("first reject any durable `retained-worktree` record")
        process_projection = contracts.index(
            "retention-root process-only free-space projection", retained_gate
        )
        process_shortfall = contracts.index("proved shortfall as `blocked-retention`", process_projection)
        checkout_projection = contracts.index(
            "only if that passes, add the checkout-root and Git-admin headroom",
            process_shortfall,
        )
        checkout_shortfall = contracts.index(
            "newly introduced physical shortfall as `blocked-worktree-capacity`",
            checkout_projection,
        )
        self.assertLess(retained_gate, process_projection)
        self.assertLess(process_projection, process_shortfall)
        self.assertLess(process_shortfall, checkout_projection)
        self.assertLess(checkout_projection, checkout_shortfall)
        readiness_retained_gate = readiness.index(
            "first reject any durable `retained-worktree` record"
        )
        readiness_process_gate = readiness.index(
            "first apply the 512 MiB process cap", readiness_retained_gate
        )
        readiness_checkout_gate = readiness.index(
            "only if it passes, add checkout headroom", readiness_process_gate
        )
        self.assertLess(readiness_retained_gate, readiness_process_gate)
        self.assertLess(readiness_process_gate, readiness_checkout_gate)
        self.assertLess(
            readiness.index("group their unallocated physical headroom"),
            readiness.index("authoritative `phase=reserved` record"),
        )
        self.assertLess(
            contracts.index("add the proposed 257 MiB process-artifact envelope"),
            contracts.index("After admission succeeds"),
        )

    def test_prompt_artifact_is_reserved_before_materialization(self) -> None:
        tool_root = SCRIPTS / "independent_codex_pr_review"
        supervisor = (tool_root / "review_supervisor/supervisor.py").read_text(
            encoding="utf-8"
        )
        ledger = (tool_root / "review_supervisor/ledger.py").read_text(
            encoding="utf-8"
        )
        runtime = (tool_root / "review_supervisor/runtime.py").read_text(
            encoding="utf-8"
        )
        runtime_tests = (tool_root / "tests/test_runtime_helpers.py").read_text(
            encoding="utf-8"
        )
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        run_start = supervisor.index("def run(")
        preparation = supervisor.index(
            "prepared = _prepare_with_reclamation(", run_start
        )
        reservation = supervisor.index(
            "attempt_dir, state, state_digest = create_reserved_attempt(",
            preparation,
        )
        publication = supervisor.index(
            "state, state_digest = publish_prompt_via_helper(", reservation
        )
        supervisor_spawn = supervisor.index(
            "supervisor = _spawn_attempt_supervisor(", publication
        )
        self.assertLess(preparation, reservation)
        self.assertLess(reservation, publication)
        self.assertLess(publication, supervisor_spawn)

        create_start = ledger.index("def create_reserved_attempt(")
        create_end = ledger.index("\ndef ", create_start + 1)
        create_body = ledger[create_start:create_end]
        for invariant in (
            '"phase": "reserved"',
            '"worktree_status": "absent"',
            '"launch_status": "not-attempted"',
            '"prompt_length": len(prompt)',
            '"prompt_sha256": prompt_sha256',
            'atomic_write_json(attempt_dir / "state.json", state, replace=False)',
        ):
            self.assertIn(invariant, create_body)
        self.assertNotIn("publish_bytes(", create_body)

        helper_start = runtime.index("def prompt_helper_main(")
        helper_end = runtime.index("\ndef publish_prompt_via_helper(", helper_start)
        helper_body = runtime[helper_start:helper_end]
        evidence = helper_body.index("evidence = prompt_evidence(prompt)")
        predecessor = helper_body.index(
            'if digest != request.get("predecessor_sha256"):', evidence
        )
        reservation_match = helper_body.index(
            '"length": state["prompt_length"]', predecessor
        )
        publish = helper_body.index("identity = publish_bytes(prompt_path, prompt)")
        commit = helper_body.index("next_state, next_digest = commit_state(", publish)
        self.assertLess(evidence, predecessor)
        self.assertLess(predecessor, reservation_match)
        self.assertLess(reservation_match, publish)
        self.assertLess(publish, commit)

        for value in (readiness, contracts):
            self.assertIn("phase=reserved", value)
            self.assertIn("prompt", value)
        self.assertIn(
            "def test_prompt_verifier_uses_private_handoff_bytes_and_durable_identity",
            runtime_tests,
        )

    def test_phase_writer_holds_publication_lease_until_exit(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("same-open-file-description BSD `flock`", readiness)
        self.assertIn("expected predecessor generation/SHA-256", readiness)
        self.assertIn("successor cannot acquire the lock", readiness)
        self.assertIn("same locked open-file-description", contracts)
        self.assertIn("must not reopen the lock path", contracts)
        self.assertIn("never calls `LOCK_UN` while a phase helper lives", contracts)
        self.assertIn("publication lease continues to exclude successor owners", contracts)
        self.assertIn("`record_generation`", contracts)
        self.assertIn("`previous_record_sha256`", contracts)

    def test_raw_materializer_prevalidates_and_atomically_installs_symlinks(
        self,
    ) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        contract_expectations = (
            (
                readiness,
                "exact payload/delimiter",
                "`.git`-resolving",
                "cached head target is not reread or charged twice",
            ),
            (
                contracts,
                "exact payload and batch delimiter",
                "resolves into `.git`",
                "cached head target is neither reread nor charged again",
            ),
        )
        for contract, delimiter, git_rejection, cache_accounting in contract_expectations:
            self.assertIn("bounded symlink-target-only pre-materialization", contract)
            self.assertIn("frozen base and head manifests", contract)
            self.assertIn("requested object ID", contract)
            self.assertIn("returned `blob` type", contract)
            self.assertIn("manifest-declared length", contract)
            self.assertIn(delimiter, contract)
            self.assertIn("recomputed repository-object-format digest", contract)
            self.assertIn("producer success", contract)
            self.assertIn("final stdout EOF", contract)
            self.assertIn("at most 16 KiB", contract)
            self.assertIn("existing 512 MiB aggregate raw-blob limit", contract)
            self.assertIn(git_rejection, contract)
            self.assertIn(cache_accounting, contract)
            self.assertRegex(
                contract,
                r"no regular-file(?: blob)? or retained-diff payload",
            )
            self.assertIn("executes no hook or filter", contract)
            self.assertIn("performs no lazy fetch", contract)
            self.assertIn("accesses no network", contract)

        self.assertIn("ordinary placeholders for both regular and symlink leaves", readiness)
        self.assertIn("`RENAME_EXCHANGE` or `RENAME_SWAP`", readiness)
        self.assertIn("Never use unlink-then-symlink", readiness)
        self.assertIn("`blocked-checkout-atomic-symlink`", readiness)

        self.assertIn("No final symlink exists in phase 1", contracts)
        self.assertIn("alias-free reserved sibling name", contracts)
        self.assertIn("`renameat2(..., RENAME_EXCHANGE)`", contracts)
        self.assertIn("`renameatx_np(..., RENAME_SWAP)`", contracts)
        self.assertIn("never fall back to unlink-then-symlink", contracts)
        self.assertIn("never follows a manifest or newly installed symlink", contracts)
        self.assertIn("final name to have the staged symlink identity", contracts)
        self.assertIn("staging name to have the original placeholder identity", contracts)
        self.assertIn("exact `readlinkat` bytes", contracts)
        self.assertIn(
            "Absolute, transiently escaping, ultimately escaping, looping, or unstable",
            contracts,
        )
        self.assertNotIn("each final symlink with `symlinkat`", contracts)

        ordered_anchors = (
            (
                readiness,
                (
                    "establish the target filesystem's name-equivalence semantics",
                    "bounded symlink-target-only pre-materialization pass",
                    "validate the complete base/head symlink graph",
                    "may the worker build the exclusive no-follow skeleton",
                    "one real owner-only `.codex-review` directory",
                    "During subsequent regular-file materialization",
                    "content-only Git LFS v1 pointer check",
                    "use the authenticated cached target without another blob read",
                    "create and verify one alias-free staged symlink",
                    "During the 10-minute checkout deadline",
                ),
            ),
            (
                contracts,
                (
                    "Before consuming any ordinary-file blob or retained-diff payload",
                    "Phase 0 is a bounded symlink-target-only pre-materialization read",
                    "complete graph/control-namespace validation precedes",
                    "Phase 1 is an authoritative metadata-only skeleton",
                    "one real `.codex-review` directory created mode `0700`",
                    "For each regular-file blob",
                    "content-only Git LFS v1 pointer check",
                    "retrieve its Phase 0 target from the authenticated cache",
                    "create one staged symlink",
                    "Atomically exchange the staged symlink",
                    "Seal the retained primary diff during phase 2",
                ),
            ),
        )
        for content, anchors in ordered_anchors:
            positions = [content.index(anchor) for anchor in anchors]
            self.assertEqual(positions, sorted(positions), anchors)

    def test_raw_materializer_blocks_reference_compatible_lfs_pointers(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        for contract in (readiness, contracts):
            self.assertIn(
                "declared raw blob size is strictly less than 1024 bytes",
                contract,
            )
            self.assertIn("**nonempty**", contract)
            self.assertIn("Empty", contract)
            self.assertIn("harmless/pass-through", contract)
            self.assertIn("`lfs.DecodePointer`", contract)
            self.assertIn("`http://git-media.io/v/2`", contract)
            self.assertIn("`https://hawser.github.com/spec/v1`", contract)
            self.assertIn("`https://git-lfs.github.com/spec/v1`", contract)
            self.assertIn("outer whitespace", contract)
            self.assertIn("CRLF", contract)
            self.assertIn("zero-length `ScanLines` records", contract)
            self.assertIn("internal whitespace-only line", contract)
            self.assertIn("missing final LF", contract)
            self.assertIn("version` -> `oid` -> `size", contract)
            self.assertIn("extensions", contract)
            self.assertIn("unsorted", contract)
            self.assertIn("64 lowercase hexadecimal digits", contract)
            self.assertIn("nonnegative base-10 signed-64-bit integer", contract)
            self.assertIn("`+0001`", contract)
            self.assertIn("`-0`", contract)
            self.assertIn("duplicate", contract)
            self.assertIn(
                "invalid version/oid/size/extension near-misses",
                contract.lower(),
            )
            self.assertIn("`blocked-checkout-lfs-pointer`", contract)
            self.assertIn("`review_status=not-run`", contract)
            self.assertIn("`.gitattributes`", contract)
            self.assertIn("`git lfs`", contract)
            self.assertIn("download LFS content", contract)
            self.assertIn("access the network", contract)

        self.assertIn("buffer capped at 1023 bytes", contracts)
        self.assertIn("Independently of every attribute result", contracts)
        self.assertIn(
            "existing frozen-head attribute query remains a second independent gate",
            contracts,
        )
        self.assertIn("deletes or rewrites `.gitattributes`", contracts)
        self.assertIn("deleting or rewriting `.gitattributes`", readiness)
        self.assertIn("must not invoke `git lfs`", contracts)
        self.assertIn("do not invoke `git lfs`", readiness)
        self.assertIn("same-key map overwrite", contracts)
        self.assertIn("one decimal priority digit `0..9`", contracts)
        self.assertIn("a nonblank extension after `size` is rejected", contracts)
        self.assertIn("blobs of at least 1024 bytes are outside", readiness)
        self.assertIn("neither gate substitutes for the other", contracts)
        self.assertIn("neither gate substitutes for the other", readiness)
        self.assertLess(
            contracts.index("content-only Git LFS v1 pointer check"),
            contracts.index(
                "existing frozen-head attribute query remains a second independent gate"
            ),
        )
        self.assertIn("never the sole LFS-pointer detector", readiness)

        oid = b"a" * 64
        canonical = (
            b"version https://git-lfs.github.com/spec/v1\n"
            b"oid sha256:" + oid + b"\nsize 1\n"
        )
        accepted_cases = {
            "canonical": canonical,
            "legacy-alpha": (
                b"version http://git-media.io/v/2\n"
                b"oid sha256:" + oid + b"\nsize +0001"
            ),
            "legacy-prerelease": (
                b"\r\nversion https://hawser.github.com/spec/v1\r\n\r\n"
                b"oid sha256:" + oid + b"\r\nsize -0\r\n\t"
            ),
            "noncanonical-extensions": (
                b"ext-2-z sha256:" + oid + b"\n"
                b"version https://git-lfs.github.com/spec/v1\n"
                b"ext-0-a sha256:" + oid + b"\n"
                b"oid sha256:" + oid + b"\nsize 01"
            ),
            "same-extension-key-overwrites": (
                b"ext-0-a sha256:invalid\n"
                b"ext-0-a sha256:" + oid + b"\n"
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "extension-prefix-suffix": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"ext-1-name-$$ sha256:" + oid + b"\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "unicode-outer-space": b"\xc2\xa0" + canonical + b"\xc2\xa0",
        }
        rejected_near_misses = {
            "empty": b"",
            "whitespace-only": b" \t\r\n",
            "bad-oid": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:xyz\nsize 1\n"
            ),
            "negative-size": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize -1\n"
            ),
            "extension-after-size": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
                b"ext-0-a sha256:" + oid + b"\n"
            ),
            "internal-whitespace-only-line": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"   \n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "double-space-value": (
                b"version  https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "priority-10": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"ext-10-a sha256:" + oid + b"\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "different-keys-duplicate-priority": (
                b"ext-0-a sha256:" + oid + b"\n"
                b"ext-0-b sha256:" + oid + b"\n"
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize 1\n"
            ),
            "size-overflow": (
                b"version https://git-lfs.github.com/spec/v1\n"
                b"oid sha256:" + oid + b"\nsize 9223372036854775808\n"
            ),
        }
        for name, payload in accepted_cases.items():
            with self.subTest(pointer=name):
                self.assertTrue(_git_lfs_3_7_1_reference_pointer_gate(payload))
                self.assertTrue(workspace_runtime._is_git_lfs_pointer(payload))
        for name, payload in rejected_near_misses.items():
            with self.subTest(near_miss=name):
                self.assertFalse(_git_lfs_3_7_1_reference_pointer_gate(payload))
                self.assertFalse(workspace_runtime._is_git_lfs_pointer(payload))

        pointer_1023 = canonical + (b" " * (1023 - len(canonical)))
        pointer_1024 = canonical + (b" " * (1024 - len(canonical)))
        self.assertEqual(1023, len(pointer_1023))
        self.assertTrue(_git_lfs_3_7_1_reference_pointer_gate(pointer_1023))
        self.assertTrue(workspace_runtime._is_git_lfs_pointer(pointer_1023))
        self.assertEqual(1024, len(pointer_1024))
        self.assertFalse(_git_lfs_3_7_1_reference_pointer_gate(pointer_1024))
        self.assertFalse(workspace_runtime._is_git_lfs_pointer(pointer_1024))

    def test_raw_materializer_preserves_git_executable_bit(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("for Git modes `100644` and `100755`", readiness)
        self.assertIn("exact `0644` or `0755` with `fchmod`", readiness)
        self.assertIn("filesystem executable bits", readiness)
        self.assertIn("Git regular-file modes `100644` and `100755`", contracts)
        self.assertIn("set mode `0644` or `0755` respectively", contracts)
        self.assertIn("no setuid/setgid/sticky bits", contracts)
        self.assertIn("Never infer executability", contracts)

        copied = contracts.index("after the exact raw copy")
        chmodded = contracts.index("use `fchmod`", copied)
        synced = contracts.index("`fsync` it", chmodded)
        verified = contracts.index("require `fstat`", synced)
        self.assertLess(copied, chmodded)
        self.assertLess(chmodded, synced)
        self.assertLess(synced, verified)

    def test_independent_recovery_matrix_closes_every_nonterminal_phase(self) -> None:
        readiness = (SKILL_ROOT / "references/pr-readiness.md").read_text(
            encoding="utf-8"
        )
        contracts = (SKILL_ROOT / "references/review-lane-contracts.md").read_text(
            encoding="utf-8"
        )

        phases = ("reserved", "worktree-adding", "validating", "spawn-intent", "launched")
        rows = {
            phase: next(
                line
                for line in contracts.splitlines()
                if line.startswith(f"| `{phase}` |")
            )
            for phase in phases
        }
        cleanup_row = next(
            line
            for line in contracts.splitlines()
            if line.startswith("| `prelaunch-aborted` with")
        )
        for phase in ("reserved", "worktree-adding", "validating"):
            row = rows[phase]
            self.assertIn("original owner", row)
            self.assertIn("`closure=proven-by-owner`", row)
            self.assertIn("`closure=proven-by-boot-change`", row)

        spawn_row = rows["spawn-intent"]
        self.assertIn("Durable completed handoff", spawn_row)
        self.assertIn("live supervisor as original owner", spawn_row)
        self.assertIn("`closure=proven-by-owner`", spawn_row)
        self.assertIn("`closure=proven-by-boot-change`", spawn_row)
        self.assertIn("full charges", spawn_row)
        self.assertNotIn("incomplete handoff", spawn_row)

        launched_row = rows["launched"]
        self.assertIn("`handoff=complete` live supervisor", launched_row)
        self.assertIn("original owner", launched_row)
        self.assertIn("`closure=proven-by-owner`", launched_row)
        self.assertIn("`closure=proven-by-boot-change`", launched_row)
        self.assertIn("full envelope", launched_row)

        self.assertIn("`cleanup=pending` or `cleanup=running`", cleanup_row)
        self.assertIn("same-boot original owner", cleanup_row)
        self.assertIn("`closure=proven-by-owner`", cleanup_row)
        self.assertIn("`closure=proven-by-boot-change`", cleanup_row)
        self.assertIn("`review_status=not-run`", cleanup_row)
        self.assertIn("exact-settlement tuple", cleanup_row)

        for phase in ("reserved", "worktree-adding", "validating"):
            self.assertIn("`phase=prelaunch-aborted`", rows[phase])
            self.assertIn("`review_status=not-run`", rows[phase])

        self.assertIn("`launch_status=uncertain`", rows["spawn-intent"])
        self.assertIn("`review_status=inconclusive`", rows["spawn-intent"])
        self.assertIn("`launch_status=launched`", rows["launched"])
        self.assertIn("`review_status=inconclusive`", rows["launched"])
        self.assertIn("outer-process loss", rows["launched"])
        self.assertIn("latches abandonment", rows["launched"])
        self.assertIn("`process_settlement=outstanding`", contracts)
        self.assertIn("full 257 MiB envelope", contracts)
        self.assertIn("`retained_process_bytes=<exact>`", contracts)
        self.assertIn(
            "`process_settlement=exact` may coexist with "
            "`checkout_settlement=outstanding`",
            contracts,
        )
        self.assertNotIn("`launched` follows active-attempt recovery", contracts)
        self.assertIn("Recovery follows the exhaustive matrix", readiness)
        self.assertIn(
            "process settlement remains independent from checkout and cleanup/logging settlement",
            readiness,
        )

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

    def test_approval_template_excludes_authentication_from_copilot_fallback(
        self,
    ) -> None:
        consent = (SKILL_ROOT / "references/egress-consent.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "secure Claude runtime is deterministically absent/unavailable",
            consent,
        )
        self.assertIn(
            "both pinned Claude Opus models are entitlement-blocked",
            consent,
        )
        self.assertIn(
            "Claude authentication failure pauses as `blocked-authentication`",
            consent,
        )
        self.assertNotIn("has no usable local/API authentication", consent)

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
