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

    def test_cli_uses_fresh_auth_only_codex_home(self) -> None:
        local = _read("local-codex-lane.md")
        contracts = _read("review-lane-contracts.md")
        prompts = _read("review-prompt-templates.md")
        normalized = _normalized(local)

        for required in (
            "Never give a canonical CLI lane the ambient or ordinary user `CODEX_HOME`",
            "automatically loads `AGENTS.override.md` or `AGENTS.md` from that home",
            "fresh, owner-private temporary `CODEX_HOME`",
            "child environment: CODEX_HOME=<absolute-owner-private-temporary-auth-only-home>",
            'cli_auth_credentials_store="file"',
            "exact mode `0600`",
            "exact mode `0700`",
            "real parent directories owned by the launching user or a separately trusted root identity",
            "no group or other write bit",
            "group/other traverse or read bits are not mutation evidence and are allowed",
            "descriptor-to-descriptor byte copy",
            "source path-object identity, access policy, byte length, and SHA-256 digest",
            "never copy a refreshed value back to the source",
            "blocked-authentication",
            "blocked-safety",
            "peer subagent adapter with the same requested profile",
            "credential-preserving `codex login status` check",
            '<absolute-codex> -c cli_auth_credentials_store="file" login status',
            "actual review `exec` receives its own fresh auth-only home",
            "distinct from every status or diagnostic home",
            "complete structured terminal event prove actual flag use",
            "Do not run a separate paid model `exec` preflight on every review",
            "optional diagnostic does not count as a review",
            "not a clean-result prerequisite",
            "Raw credential bytes are Codex runtime authentication material only",
            "The Codex runtime must read the temporary `auth.json`",
            "trusted-processor boundary, not OS-level credential isolation",
            "authentication credential discovery",
            "read, search for, or output the temporary `CODEX_HOME`",
            "do not by themselves prove deny-read separation",
            "not a filesystem deny-read control",
        ):
            self.assertIn(required.lower(), normalized.lower())

        self.assertIn(
            "Immediately before an authenticated CLI process, its new temporary home's inventory is exactly `auth.json`",
            normalized,
        )
        self.assertIn(
            "report-and-cleanup evidence, not a closed allowlist or input to another process",
            normalized,
        )
        for transient in (
            "installation_id",
            ".sandbox_migration",
            "cache",
            "models_cache.json",
            "shell_snapshots",
            "tmp",
        ):
            self.assertIn(f"`{transient}`", local)
        self.assertNotIn("`models_cache`", local)
        self.assertIn(
            "Any `AGENTS*`, config, skill, plugin, rule, or hook path", normalized
        )
        self.assertIn("Classify a session or history path as sensitive", normalized)
        self.assertIn("Never purge a home for reuse", normalized)
        self.assertIn(
            "never carry any postlaunch state into another process", normalized
        )
        self.assertIn(
            "incomplete credential cleanup prevents a clean CLI result", normalized
        )
        self.assertNotIn("owner-only real parent directories", local)
        self.assertNotIn("exposes them to the reviewer", local)
        self.assertNotIn("authenticated preflight status", local)
        self.assertNotIn(
            "run one bounded credential-preserving failure/status preflight", local
        )

        self.assertIn("version-bound hostile-home control", normalized)
        self.assertIn("injects that marker", normalized)
        self.assertIn("fresh empty temporary `CODEX_HOME`", normalized)
        self.assertIn("none of the global, project, or skill markers", normalized)
        self.assertNotIn(
            "Populate the probe home with unique synthetic global `AGENTS.md`",
            local,
        )

        cli_argv = local.split("normalized direct-argv shape is:", 1)[1].split(
            "```", 2
        )[1]
        self.assertIn('-c cli_auth_credentials_store="file"', cli_argv)
        self.assertIn(
            '-c shell_environment_policy.filters={CODEX_HOME="exclude"}', cli_argv
        )
        self.assertIn(
            "-c shell_environment_policy.ignore_default_excludes=false", cli_argv
        )
        self.assertFalse(
            any(
                line.strip().startswith("CODEX_HOME=") for line in cli_argv.splitlines()
            )
        )

        for document in (contracts, prompts):
            self.assertIn("auth-only `CODEX_HOME`", document)
            self.assertIn("authentication credential discovery", document)
            self.assertIn("auth.json", document)
        self.assertIn("auth_only_codex_home_receipt:", prompts)

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
