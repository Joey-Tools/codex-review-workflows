from __future__ import annotations

import pathlib
import unittest


SKILL_ROOT = pathlib.Path(__file__).resolve().parents[1]
REFERENCES = SKILL_ROOT / "references"


def _read(name: str) -> str:
    return (REFERENCES / name).read_text(encoding="utf-8")


def _normalized(value: str) -> str:
    return " ".join(value.split())


class LocalCodexLaneContractTest(unittest.TestCase):
    def test_cli_isolates_automatic_guidance_for_self_policy_review(self) -> None:
        local = _read("local-codex-lane.md")
        contracts = _read("review-lane-contracts.md")
        prompts = _read("review-prompt-templates.md")

        for control in (
            "--ignore-user-config",
            "--ignore-rules",
            "project_doc_max_bytes=0",
            "skills.include_instructions=false",
            "skills.bundled.enabled=false",
            "--disable plugins",
            "--disable hooks",
            "--skip-git-repo-check",
        ):
            self.assertIn(control, local)

        for document in (local, contracts, prompts):
            self.assertIn("neutral launch", document.lower())
            self.assertIn("instruction-surface", document.lower())
            self.assertIn("candidate", document.lower())
            self.assertIn("review-subject", document)
            self.assertIn("scoped-convention", document)

        self.assertIn("candidate_scoped_conventions:", prompts)
        self.assertIn("sha256: <lowercase SHA-256>", prompts)
        self.assertIn(
            "Do not activate a skill, plugin, rule, hook, agent, config layer",
            _normalized(prompts),
        )
        self.assertIn(
            "Any automatic candidate/user guidance injection makes",
            contracts,
        )

        cli_argv = local.split("normalized direct-argv shape is:", 1)[1].split(
            "```", 2
        )[1]
        self.assertIn("-C <absolute-parent-owned-neutral-launch-directory>", cli_argv)
        self.assertIn("--skip-git-repo-check", cli_argv)
        self.assertNotIn("-C <absolute-validated-workspace>", cli_argv)
        self.assertIn(
            "Never use the legacy `-C <absolute-validated-workspace>` shape",
            _normalized(local),
        )
        self.assertIn(
            "`debug prompt-input` does not accept the exec-only `--strict-config`,",
            local,
        )
        self.assertIn(
            "verifies only the model-visible guidance controls it accepts",
            _normalized(local),
        )

    def test_peer_adapters_share_fail_closed_effective_profile_matrix(self) -> None:
        local = _read("local-codex-lane.md")
        contracts = _read("review-lane-contracts.md")
        prompts = _read("review-prompt-templates.md")

        for document in (local, contracts, prompts):
            for basis in (
                "runtime-attested",
                "accepted-pinned-launch",
                "unknown",
                "mismatch",
            ):
                self.assertIn(basis, document)
            self.assertIn("inconclusive", document)

        matrix = local.split(
            "Use this effective-profile outcome matrix for both peer adapters:", 1
        )[1].split("For the CLI,", 1)[0]
        self.assertIn(
            "| `runtime-attested` exact match | Attested model and mode | Yes",
            matrix,
        )
        self.assertIn(
            "| `accepted-pinned-launch` with no contradictory telemetry | Requested pinned model and mode | Yes",
            matrix,
        )
        self.assertIn(
            "| `unknown` | `unknown` for every unproved field | No; the lane is `inconclusive`.",
            matrix,
        )
        self.assertIn(
            "| `mismatch` | Observed substituted or downgraded values | No; the lane is `inconclusive`.",
            matrix,
        )
        self.assertIn("`unknown` is never clean", local)
        self.assertIn("`unknown` and `mismatch` are always inconclusive", contracts)
        self.assertIn("provider backend aliases", contracts)

    def test_current_pinned_profile_and_peer_identity_remain_explicit(self) -> None:
        local = _read("local-codex-lane.md")
        contracts = _read("review-lane-contracts.md")

        for expected in (
            "gpt-5.6-sol",
            'model_reasoning_effort="ultra"',
            'fork_turns="none"',
            "Neither adapter has a standing priority",
        ):
            self.assertIn(expected, local)
        self.assertIn("peer adapters", contracts)

    def test_always_read_github_contracts_use_closed_recovery_semantics(self) -> None:
        contracts = _read("review-lane-contracts.md")
        prompts = _read("review-prompt-templates.md")
        normalized_contracts = _normalized(contracts)
        normalized_prompts = _normalized(prompts)

        for required in (
            "no applicable unresolved provider finding passes",
            "only applicable unresolved provider findings block",
            "exact typed GraphQL thread resolution",
            "later trustworthy provider correction",
            "machine-decidable transient pending or infrastructure reason",
            "repository-predeclared idempotent or reentrant contract",
            "current authorization for the external mutation",
            "it never authorizes another POST",
            "The GitHub write is not intrinsically idempotent",
            "neither alone changes code, creates a head, or invalidates stable local reviews",
            "If resolving a finding changes code",
        ):
            self.assertIn(required.lower(), normalized_contracts.lower())

        self.assertIn(
            "single-flight read/reread recovery and never repeat the POST",
            normalized_prompts,
        )
        self.assertIn(
            "the GitHub write is not intrinsically idempotent", normalized_prompts
        )

        for retired in (
            "Explicit provider findings block.",
            "missing/stale/inconclusive/infrastructure",
            "single-flight idempotent repeat",
            "single-flight, idempotent producer recovery",
        ):
            self.assertNotIn(retired, contracts + "\n" + prompts)


if __name__ == "__main__":
    unittest.main()
