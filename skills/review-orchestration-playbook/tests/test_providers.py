from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import providers  # noqa: E402
from review_runtime.common import Completed  # noqa: E402
from review_runtime.workspace import ReviewWorkspace  # noqa: E402


class ProviderPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temporary.name)
        workspace = root / "workspace"
        workspace.mkdir()
        diff_file = root / "review.diff"
        diff_file.write_text("diff --git a/a b/a\n", encoding="utf-8")
        prompt_file = root / "review.prompt"
        prompt_file.write_text("Review this diff.\n", encoding="utf-8")
        self.review = ReviewWorkspace(
            source_root=root,
            container_dir=root,
            workspace_root=workspace,
            base_ref="a" * 40,
            head_ref="b" * 40,
            diff_file=diff_file,
            prompt_file=prompt_file,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def attempt(
        self,
        runtime: str,
        model: str,
        category: str,
        *,
        final_text: str | None = None,
    ) -> providers.Attempt:
        return providers.Attempt(
            runtime=runtime,
            requested_model=model,
            effective_model=model if final_text else None,
            returncode=0 if final_text else 1,
            category=category,
            final_text=final_text,
            stdout_path=str(self.review.container_dir / "stdout"),
            stderr_path=str(self.review.container_dir / "stderr"),
        )

    def test_capacity_wins_over_unavailable_wording(self) -> None:
        category = providers.classify_failure(
            "",
            "Selected model is temporarily unavailable because it is at capacity",
        )
        self.assertEqual(category, "transient")

    def test_entitlement_is_fallback_eligible(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Model is not available for your account"),
            "entitlement",
        )
        self.assertEqual(
            providers.classify_failure(
                "",
                "This model is not supported with your ChatGPT account",
            ),
            "entitlement",
        )

    def test_auth_is_not_entitlement(self) -> None:
        self.assertEqual(
            providers.classify_failure("", "Authentication failed: invalid token"),
            "auth",
        )

    def test_auth_wins_over_entitlement_wording(self) -> None:
        self.assertEqual(
            providers.classify_failure(
                "",
                "Unauthorized: model is not available for your account",
            ),
            "auth",
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_falls_back_from_56_to_55_only_on_entitlement(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.side_effect = (
            self.attempt("codex", "gpt-5.6-sol", "entitlement"),
            self.attempt("codex", "gpt-5.5", "success", final_text="No findings."),
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
            shim_source=SCRIPTS / "git_readonly_shim",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [item.requested_model for item in outcome.attempts],
            list(providers.CODEX_MODELS),
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(providers, "_codex_attempt")
    def test_codex_capacity_does_not_downgrade(
        self,
        codex_attempt: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        codex_attempt.return_value = self.attempt("codex", "gpt-5.6-sol", "transient")
        outcome = providers.run_review(
            review=self.review,
            reviewer="codex",
            shim_source=SCRIPTS / "git_readonly_shim",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(codex_attempt.call_count, 1)

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_family_order_is_claude_48_47_then_copilot_48_47(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.side_effect = tuple(
            self.attempt("claude", model, "entitlement")
            for model in providers.CLAUDE_MODELS
        )
        copilot_attempt.side_effect = (
            self.attempt("copilot", providers.COPILOT_MODELS[0], "entitlement"),
            self.attempt(
                "copilot",
                providers.COPILOT_MODELS[1],
                "success",
                final_text="No findings.",
            ),
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            shim_source=SCRIPTS / "git_readonly_shim",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 0)
        self.assertEqual(
            [(item.runtime, item.requested_model) for item in outcome.attempts],
            [
                ("claude", "claude-opus-4-8"),
                ("claude", "claude-opus-4-7"),
                ("copilot", "claude-opus-4.8"),
                ("copilot", "claude-opus-4.7"),
            ],
        )

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_claude_capacity_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude", "claude-opus-4-8", "transient"
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            shim_source=SCRIPTS / "git_readonly_shim",
            egress_consent="triple-review",
        )
        self.assertEqual(outcome.returncode, 75)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    @mock.patch.object(providers, "child_environment", return_value={})
    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/true")
    )
    @mock.patch.object(providers, "_copilot_attempt")
    @mock.patch.object(providers, "_claude_attempt")
    def test_model_mismatch_does_not_switch_model_or_backend(
        self,
        claude_attempt: mock.Mock,
        copilot_attempt: mock.Mock,
        _resolve: mock.Mock,
        _environment: mock.Mock,
    ) -> None:
        claude_attempt.return_value = self.attempt(
            "claude",
            "claude-opus-4-8",
            "model-mismatch",
        )
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            shim_source=SCRIPTS / "git_readonly_shim",
            egress_consent="double-review",
        )
        self.assertEqual(outcome.returncode, 1)
        self.assertEqual(claude_attempt.call_count, 1)
        copilot_attempt.assert_not_called()

    def test_effective_model_substitution_does_not_infer_entitlement(self) -> None:
        completed = Completed(
            argv=("claude",),
            returncode=0,
            stdout=json.dumps(
                {"result": "No findings.", "modelUsage": {"claude-opus-4-7": {}}}
            ).encode(),
            stderr=b"",
        )
        attempt = providers._record_attempt(
            review=self.review,
            index=1,
            runtime="claude",
            model="claude-opus-4-8",
            completed=completed,
            final_text="No findings.",
            effective_model="claude-opus-4-7",
        )
        self.assertEqual(attempt.category, "model-mismatch")
        self.assertIsNone(attempt.final_text)

    @mock.patch.object(providers, "child_environment", return_value={})
    def test_claude_lane_requires_explicit_egress_consent(
        self,
        _environment: mock.Mock,
    ) -> None:
        outcome = providers.run_review(
            review=self.review,
            reviewer="claude",
            shim_source=SCRIPTS / "git_readonly_shim",
        )
        self.assertEqual(outcome.returncode, 2)
        self.assertIn(
            "explicit egress-consent",
            (self.review.container_dir / "runner-error.txt").read_text(
                encoding="utf-8"
            ),
        )

    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/codex")
    )
    @mock.patch.object(providers, "run")
    def test_codex_command_pins_model_and_reasoning(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        def complete(argv, **_kwargs):
            argv = tuple(argv)
            final_path = pathlib.Path(argv[argv.index("-o") + 1])
            final_path.parent.mkdir(parents=True, exist_ok=True)
            final_path.write_text("No findings.\n", encoding="utf-8")
            return Completed(argv=argv, returncode=0, stdout=b"", stderr=b"")

        run_command.side_effect = complete
        providers._codex_attempt(
            review=self.review, model="gpt-5.6-sol", index=1, env={}
        )
        argv = run_command.call_args.args[0]
        self.assertIn("gpt-5.6-sol", argv)
        self.assertIn('model_reasoning_effort="xhigh"', argv)

    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/claude")
    )
    @mock.patch.object(providers, "run")
    def test_claude_command_pins_opus_and_max(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        payload = {"result": "No findings.", "modelUsage": {"claude-opus-4-8": {}}}
        run_command.return_value = Completed(
            argv=("claude",),
            returncode=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )
        providers._claude_attempt(
            review=self.review,
            model="claude-opus-4-8",
            index=1,
            env={},
        )
        argv = run_command.call_args.args[0]
        self.assertIn("claude-opus-4-8", argv)
        self.assertEqual(argv[argv.index("--effort") + 1], "max")
        self.assertEqual(argv[argv.index("--tools") + 1], "Read,Grep,Glob")
        self.assertIn("--strict-mcp-config", argv)

    @mock.patch.object(
        providers, "resolve_executable", return_value=pathlib.Path("/bin/copilot")
    )
    @mock.patch.object(providers, "run")
    def test_copilot_command_pins_opus_and_max(
        self,
        run_command: mock.Mock,
        _resolve: mock.Mock,
    ) -> None:
        payload = {"result": "No findings.", "model": "claude-opus-4.8"}
        run_command.return_value = Completed(
            argv=("copilot",),
            returncode=0,
            stdout=json.dumps(payload).encode(),
            stderr=b"",
        )
        providers._copilot_attempt(
            review=self.review,
            model="claude-opus-4.8",
            index=1,
            env={"GH_TOKEN": "secret"},
        )
        argv = run_command.call_args.args[0]
        self.assertIn("claude-opus-4.8", argv)
        self.assertEqual(argv[argv.index("--reasoning-effort") + 1], "max")
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertIn("--disable-builtin-mcps", argv)
        self.assertIn("--no-custom-instructions", argv)
        self.assertIn("--secret-env-vars=GH_TOKEN", argv)


if __name__ == "__main__":
    unittest.main()
