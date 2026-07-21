from __future__ import annotations

import pathlib
import sys
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

from review_runtime import claude_capabilities as capabilities  # noqa: E402


def supported_help(*, safe_mode: str | None = None) -> str:
    safe_mode = safe_mode or (
        "Start with all customizations (CLAUDE.md, skills, plugins, hooks, MCP "
        "servers, custom commands and agents, output styles, workflows, custom "
        "themes, keybindings, and more) disabled. Admin-managed (policy) settings "
        "still apply. Auth, model selection, built-in tools, and permissions work "
        "normally. Sets CLAUDE_CODE_SAFE_MODE=1."
    )
    lines = ["Usage: claude [options]", "", "Options:"]
    for option in capabilities.CLAUDE_REQUIRED_OPTIONS:
        if option == "--safe-mode":
            description = safe_mode
        elif option == "--permission-mode":
            description = "Permission mode (choices: default, dontAsk, plan)."
        else:
            description = "Supported option."
        lines.append(f"  {option} <value>  {description}")
    return "\n".join(lines) + "\n"


class ClaudeCapabilitiesTest(unittest.TestCase):
    def test_version_range_floats_within_major_two(self) -> None:
        for version in ("2.1.211", "2.1.212", "2.1.216", "2.99.999"):
            with self.subTest(version=version):
                parsed = capabilities.parse_claude_version(f"{version} (Claude Code)\n")
                self.assertEqual(parsed.text, version)

    def test_version_range_rejects_old_next_major_and_prerelease(self) -> None:
        for output in (
            "2.1.210 (Claude Code)\n",
            "3.0.0 (Claude Code)\n",
            "2.1.211-beta.1 (Claude Code)\n",
            "2.1.211 (Claude Code)\nextra\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(capabilities.ClaudeCapabilityError):
                    capabilities.parse_claude_version(output)

    def test_version_range_rejects_oversized_numeric_components(self) -> None:
        for output in (
            f"2.{'9' * 10}.1 (Claude Code)\n",
            f"{'9' * 5000}.1.1 (Claude Code)\n",
        ):
            with self.subTest(output_length=len(output)):
                with self.assertRaises(capabilities.ClaudeCapabilityError):
                    capabilities.parse_claude_version(output)

    def test_help_accepts_semantic_wording_changes(self) -> None:
        options, block = capabilities.validate_claude_help(supported_help())

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)
        self.assertIn("admin-managed", block)

    def test_help_accepts_bounded_information_and_positive_wording_changes(
        self,
    ) -> None:
        safe_mode = (
            "Documentation about safe mode remains available online. Start with all "
            "customizations (CLAUDE.md, skills, plugins, hooks, MCP servers, "
            "custom commands and agents, output styles, workflows, custom themes, "
            "keybindings, and more) disabled. Managed policy settings remain "
            "active. Authentication, permissions, built-in tools, and model "
            "selection remain available. CLAUDE_CODE_SAFE_MODE=1."
        )

        options, _block = capabilities.validate_claude_help(
            supported_help(safe_mode=safe_mode)
        )

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_requires_every_option_used_by_final_command(self) -> None:
        help_text = supported_help().replace(
            "  --strict-mcp-config <value>  Supported option.\n",
            "",
        )

        with self.assertRaisesRegex(
            capabilities.ClaudeCapabilityUnavailable,
            "required review option",
        ):
            capabilities.validate_claude_help(help_text)

    def test_help_requires_verbose_for_stream_json_launch(self) -> None:
        help_text = supported_help().replace(
            "  --verbose <value>  Supported option.\n",
            "",
        )

        with self.assertRaisesRegex(
            capabilities.ClaudeCapabilityUnavailable,
            "required review option",
        ):
            capabilities.validate_claude_help(help_text)

    def test_help_requires_dont_ask_permission_mode_before_credentials(self) -> None:
        help_text = supported_help().replace("dontAsk, ", "")

        with self.assertRaisesRegex(
            capabilities.ClaudeCapabilityUnavailable,
            "required dontAsk choice",
        ):
            capabilities.validate_claude_help(help_text)

    def test_help_rejects_duplicate_safe_mode_declaration(self) -> None:
        help_text = supported_help() + "  --safe-mode  Hooks still load.\n"

        with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
            capabilities.validate_claude_help(help_text)

    def test_help_allows_non_declaration_safe_mode_reference(self) -> None:
        help_text = supported_help() + (
            "  --betas <value>  Compatible with --safe-mode.\n"
        )

        options, _block = capabilities.validate_claude_help(help_text)

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_rejects_missing_or_conflicting_safe_mode_semantics(self) -> None:
        base = supported_help()
        for help_text in (
            base.replace("plugins, hooks, MCP", "plugins, MCP"),
            base.replace("hooks, MCP", "hooks enabled, MCP"),
            base.replace("CLAUDE_CODE_SAFE_MODE=1", "CLAUDE_CODE_SAFE_MODE=0"),
            base.replace("Auth, model selection", "Model selection"),
            base.replace("Admin-managed (policy) settings still apply. ", ""),
        ):
            with self.subTest(help_text=help_text):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_negated_required_safe_mode_claims(self) -> None:
        base = supported_help()
        for help_text in (
            base.replace(") disabled.", ") are not disabled."),
            base.replace("all customizations", "not all customizations"),
            base.replace("still apply.", "do not still apply."),
            base.replace("work normally.", "never work normally."),
            base.replace(
                "Sets CLAUDE_CODE_SAFE_MODE=1.",
                "Does not set CLAUDE_CODE_SAFE_MODE=1.",
            ),
        ):
            with self.subTest(help_text=help_text):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_ambiguous_customization_claims(self) -> None:
        base = supported_help()
        for label, help_text in (
            ("except", base.replace(") disabled.", ") disabled except hooks.")),
            ("unless", base.replace(") disabled.", ") disabled unless requested.")),
            ("no", base.replace(") disabled.", ") are in no way disabled.")),
            (
                "neither-nor",
                base.replace(
                    "Start with all customizations",
                    "Neither all customizations",
                ).replace(") disabled.", ") nor hooks are disabled."),
            ),
            (
                "without",
                base.replace(") disabled.", ") disabled without disabling hooks."),
            ),
            ("rarely", base.replace(") disabled.", ") are rarely disabled.")),
            ("seldom", base.replace(") disabled.", ") are seldom disabled.")),
            (
                "anything-but",
                base.replace(") disabled.", ") are anything but disabled."),
            ),
            (
                "comma-but",
                base.replace(") disabled.", ") disabled, but plugins may load."),
            ),
            (
                "semicolon-however",
                base.replace(") disabled.", ") disabled; however plugins load."),
            ),
            (
                "comma-yet",
                base.replace(") disabled.", ") disabled, yet plugins load."),
            ),
            ("modal", base.replace(") disabled.", ") may be disabled.")),
            (
                "only-when",
                base.replace(") disabled.", ") disabled only when requested."),
            ),
            ("if", base.replace(") disabled.", ") disabled if configured.")),
            ("default", base.replace(") disabled.", ") disabled by default.")),
            ("initially", base.replace(") disabled.", ") initially disabled.")),
            (
                "temporarily",
                base.replace(") disabled.", ") temporarily disabled."),
            ),
            (
                "then-restored-after-startup",
                base.replace(
                    ") disabled.",
                    ") disabled, then restored after startup.",
                ),
            ),
            (
                "restored",
                base.replace(") disabled.", ") disabled and restored."),
            ),
            (
                "subsequently-re-enabled",
                base.replace(
                    ") disabled.",
                    ") disabled, subsequently re-enabled.",
                ),
            ),
            (
                "unsafe-before-terminal-state",
                base.replace(
                    "Start with all customizations",
                    "All customizations",
                ).replace(
                    ") disabled.",
                    ") execute on startup and are disabled.",
                ),
            ),
            (
                "generic-customizations-restored",
                base.replace(
                    ") disabled.",
                    ") disabled. Customizations are restored.",
                ),
            ),
            (
                "temporal-prefix-without-comma",
                base.replace(
                    ") disabled.",
                    ") disabled. After startup customizations are restored.",
                ),
            ),
            (
                "interposed-temporal-clause",
                base.replace(
                    ") disabled.",
                    ") disabled. Customizations, after startup, are restored.",
                ),
            ),
            (
                "relative-clause-restoration",
                base.replace(
                    ") disabled.",
                    ") disabled. Customizations that the runtime restores after "
                    "startup are available.",
                ),
            ),
            (
                "qualified-customizations-active",
                base.replace(
                    ") disabled.",
                    ") disabled. Some customizations remain active.",
                ),
            ),
            (
                "unknown-extension-enabled",
                base.replace(
                    ") disabled.",
                    ") disabled. Extensions remain enabled.",
                ),
            ),
            (
                "unknown-extension-honored",
                base.replace(
                    ") disabled.",
                    ") disabled. Extensions are honored at startup.",
                ),
            ),
            (
                "quoted-unknown-extension-enabled",
                base.replace(
                    ") disabled.",
                    ") disabled. “Extensions remain enabled.”",
                ),
            ),
            (
                "project-instructions-apply",
                base.replace(
                    ") disabled.",
                    ") disabled. Project instructions still apply.",
                ),
            ),
            (
                "unknown-automation-enabled",
                base.replace(
                    ") disabled.",
                    ") disabled. Automations remain enabled.",
                ),
            ),
            (
                "singular-plugin-loaded",
                base.replace(
                    ") disabled.",
                    ") disabled. A plugin is loaded.",
                ),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_accepts_terminal_permanent_customization_claim(self) -> None:
        base = supported_help()
        for help_text in (
            base.replace(") disabled.", ") disabled throughout the review."),
            base.replace(") disabled.", ") disabled during safe mode."),
            base.replace(
                "Start with all customizations",
                "All customizations",
            ).replace(") disabled.", ") remain disabled throughout safe mode."),
            base.replace(
                ") disabled.",
                ") disabled for the entire duration of the review session.",
            ),
            base.replace(
                "(CLAUDE.md",
                "(\n    CLAUDE.md",
            ).replace(
                "and more) disabled.",
                "and more\n    ) disabled.",
            ),
        ):
            with self.subTest(help_text=help_text):
                options, _block = capabilities.validate_claude_help(help_text)

                self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_accepts_exact_benign_safe_mode_purpose_suffix(self) -> None:
        help_text = (
            supported_help()
            .replace("--safe-mode <value>", "--safe-mode")
            .replace(
                ") disabled.",
                ") disabled — useful for troubleshooting a broken configuration.",
            )
        )

        options, _block = capabilities.validate_claude_help(help_text)

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_allows_unrelated_customization_documentation_claims(self) -> None:
        help_text = supported_help().replace(
            "Sets CLAUDE_CODE_SAFE_MODE=1.",
            "Sets CLAUDE_CODE_SAFE_MODE=1. Documentation about customizations "
            "is available online. Information about project instructions is "
            "available online.",
        )

        options, _block = capabilities.validate_claude_help(help_text)

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_rejects_ambiguity_in_each_other_required_claim(self) -> None:
        base = supported_help()
        for label, help_text in (
            (
                "policy-exception",
                base.replace("still apply.", "still apply, except during startup."),
            ),
            (
                "runtime-contrast",
                base.replace(
                    "work normally.",
                    "work normally, but permissions may be restricted.",
                ),
            ),
            (
                "environment-contrast",
                base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    "Sets CLAUDE_CODE_SAFE_MODE=1, yet it may change.",
                ),
            ),
            (
                "policy-forbidden-state",
                base.replace("still apply.", "still apply and are ignored."),
            ),
            (
                "runtime-forbidden-state",
                base.replace(
                    "work normally.",
                    "work normally and permissions are disabled.",
                ),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_disjunctive_runtime_guarantees(self) -> None:
        base = supported_help()
        for runtime_claim in (
            "Auth or model selection or built-in tools or permissions work normally.",
            "Auth, model selection, built-in tools, or permissions work normally.",
            "Auth and model selection and built-in tools or permissions work normally.",
        ):
            with self.subTest(runtime_claim=runtime_claim):
                help_text = base.replace(
                    "Auth, model selection, built-in tools, and permissions work "
                    "normally.",
                    runtime_claim,
                )
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_requires_bounded_terms_and_rejects_conflicting_states(self) -> None:
        base = supported_help()
        for label, help_text in (
            ("undisabled", base.replace(") disabled.", ") undisabled.")),
            (
                "unauthentication",
                base.replace(
                    "Auth, model selection",
                    "Unauthentication, model selection",
                ),
            ),
            (
                "customizations-enabled",
                base.replace(") disabled.", ") are enabled and disabled."),
            ),
            (
                "separate-plugin-load",
                base.replace(") disabled.", ") disabled. Plugins load."),
            ),
            (
                "leading-contrast",
                base.replace(") disabled.", ") disabled. However, they may load."),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_anaphoric_safe_mode_reversals(self) -> None:
        base = supported_help()
        for label, help_text in (
            (
                "customization-pronoun",
                base.replace(") disabled.", ") disabled. They may still load."),
            ),
            (
                "customization-forbidden-state",
                base.replace(") disabled.", ") disabled. They load."),
            ),
            (
                "environment-pronoun",
                base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    "Sets CLAUDE_CODE_SAFE_MODE=1. It is not set.",
                ),
            ),
            (
                "environment-forbidden-state",
                base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    "Sets CLAUDE_CODE_SAFE_MODE=1. It is unset.",
                ),
            ),
            (
                "unicode-quotation-and-contraction",
                base.replace(
                    ") disabled.",
                    ") disabled. “They aren’t actually disabled.”",
                ),
            ),
            (
                "demonstrative",
                base.replace("still apply.", "still apply. Such settings may fail."),
            ),
            (
                "former",
                base.replace(
                    "work normally.",
                    "work normally. The former is unavailable.",
                ),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_explicit_safe_mode_self_reversals(self) -> None:
        base = supported_help()
        for statement in (
            "Safe mode may be disabled.",
            "Safe mode is no longer enforced.",
            "Safe mode does not apply.",
            "Safe mode is not enabled.",
            "Safe mode has been disabled.",
            "Safe mode has stopped working.",
            "Safe mode is off.",
            "Safe mode is a no-op.",
            "Safe mode is optional.",
            "Safe mode was disabled.",
            "Safe mode can be turned off.",
            "Safe mode isn't enabled.",
            "--safe-mode has no effect.",
            "Safe mode doesn't work.",
            "Administrators can bypass safe mode.",
            "Safe mode: disabled.",
            "Safe mode — disabled.",
            "Safe mode currently disabled.",
            "`--safe-mode`, however, is disabled.",
            "Safe mode's enforcement is disabled.",
            "Safe mode may not be enforced.",
            "Safe mode will no longer be supported.",
            "Safe mode fails open.",
            "Safe mode can be overridden.",
            "Safe mode is overridden.",
            "Safe mode stopped working.",
            "Safe mode is not always enforced.",
            "Safe mode is currently disabled.",
            "Safe mode may currently be disabled.",
            "Safe mode is temporarily unavailable.",
            "Safe mode has now been removed.",
            "Safe mode does not always apply.",
            "Safe mode itself is disabled.",
            "The safe mode is disabled.",
            "Safe mode cannot be enforced.",
            "Safe mode can't be enforced.",
            "Safe mode isn't currently enabled.",
            "Safe mode hasn't been enforced.",
            "In this release, safe mode is disabled.",
            "Safe mode may be deprecated.",
            "Safe mode won't be enforced.",
            "Safe mode couldn't be enforced.",
            "Safe mode may fail open.",
            "Safe mode might not work.",
            "Safe mode may no longer work.",
            "By default, safe mode is disabled.",
            "Safe mode enforcement may be disabled.",
            "Safe mode is advisory.",
            "Currently, safe mode is disabled.",
            "Safe mode could stop working.",
            "Safe mode can be switched off.",
            "Users can turn off safe mode.",
            "Users who are not administrators can disable safe mode.",
            "Not every administrator can bypass safe mode.",
            "An unrelated note is not normative; administrators can bypass safe mode.",
            "Safe-mode is disabled.",
            "Safe mode is fully enforced. It can be disabled.",
            "Safe mode cannot be disabled. It may fail open.",
            "Safe mode is fully enforced. It remains active. It can be disabled.",
            "Safe mode cannot be disabled. Users can disable it.",
            "Safe mode is fully enforced. Documentation remains available. "
            "Administrators can disable the mode.",
        ):
            with self.subTest(statement=statement):
                help_text = base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    f"Sets CLAUDE_CODE_SAFE_MODE=1. {statement}",
                )
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_accepts_positive_safe_mode_self_descriptions(self) -> None:
        base = supported_help()
        for statement in (
            "Safe mode is fully enforced.",
            "Safe mode remains active.",
            "Safe mode is supported.",
            "Disabling safe mode is not supported.",
            "Turning off safe mode is unavailable.",
            "Administrators cannot bypass safe mode.",
            "No administrator can bypass safe mode.",
            "No process can disable safe mode.",
            "Safe mode has no effect on authentication.",
            "Safe mode does not apply to managed policy settings.",
            "Safe mode has no effect on authentication or model selection.",
            "Safe mode doesn't apply to policy settings.",
            "Safe mode does not affect authentication.",
            "Safe mode does not override managed policy settings.",
            "Neither administrators nor users can bypass safe mode.",
            "Safe mode cannot be disabled.",
            "Safe mode has not been disabled.",
            "Safe mode disables all customizations.",
            "Safe mode keeps authentication and permissions working normally.",
            "Safe mode is enforced and cannot be disabled.",
            "Safe mode cannot be disabled or bypassed.",
            "Safe mode is never disabled.",
            "Hooks cannot disable safe mode.",
            "No plugins can disable safe mode.",
            "Safe mode remains enforced. It cannot be disabled.",
            "Safe mode remains enforced. It remains active. It cannot be disabled.",
            "Safe mode remains enforced. Users cannot disable it.",
            "Safe mode remains enforced. Documentation about safe mode remains "
            "available online. Users cannot disable it.",
        ):
            with self.subTest(statement=statement):
                help_text = base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    f"Sets CLAUDE_CODE_SAFE_MODE=1. {statement}",
                )
                options, _block = capabilities.validate_claude_help(help_text)

                self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_rejects_unrecognized_sentences_even_without_keyword_match(
        self,
    ) -> None:
        base = supported_help()
        for help_text in (
            base.replace(
                "Sets CLAUDE_CODE_SAFE_MODE=1.",
                "Sets CLAUDE_CODE_SAFE_MODE=1. Itemization may not matter.",
            ),
            base.replace(
                "Sets CLAUDE_CODE_SAFE_MODE=1.",
                "Sets CLAUDE_CODE_SAFE_MODE=1. The lattermost note may not matter.",
            ),
        ):
            with self.subTest(help_text=help_text):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_default_denies_unknown_customization_surfaces_and_verbs(
        self,
    ) -> None:
        base = supported_help()
        for statement in (
            ".claude/settings.json is honored at startup.",
            "CLAUDE.local.md continues to apply.",
            "Auto memory remains active.",
            "Context shims are honored at startup.",
        ):
            with self.subTest(statement=statement):
                help_text = base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    f"Sets CLAUDE_CODE_SAFE_MODE=1. {statement}",
                )
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_rejects_claims_smuggled_into_information_topic(self) -> None:
        help_text = supported_help().replace(
            "Sets CLAUDE_CODE_SAFE_MODE=1.",
            "Sets CLAUDE_CODE_SAFE_MODE=1. Documentation about auto memory that "
            "remains active is available online.",
        )

        with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
            capabilities.validate_claude_help(help_text)

    def test_help_allows_positive_anaphoric_customization_continuation(self) -> None:
        help_text = supported_help().replace(
            ") disabled.",
            ") disabled. They remain disabled.",
        )

        options, _block = capabilities.validate_claude_help(help_text)

        self.assertEqual(options, capabilities.CLAUDE_REQUIRED_OPTIONS)

    def test_help_rejects_nonadjacent_customization_anaphor(self) -> None:
        base = supported_help()
        for replacement in (
            ") disabled. Admin-managed (policy) settings still apply. They remain "
            "disabled. Auth,",
            ") disabled. Admin-managed (policy) settings still apply. Documentation "
            "about safe mode remains available online. They remain disabled. Auth,",
        ):
            with self.subTest(replacement=replacement):
                help_text = base.replace(
                    ") disabled. Admin-managed (policy) settings still apply. Auth,",
                    replacement,
                )
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)

    def test_help_requires_one_exact_safe_mode_environment_assignment(self) -> None:
        base = supported_help()
        for label, help_text in (
            ("longer-value", base.replace("=1.", "=10.")),
            ("decimal-value", base.replace("=1.", "=1.0.")),
            ("suffix-value", base.replace("=1.", "=1x.")),
            (
                "duplicate",
                base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    "Sets CLAUDE_CODE_SAFE_MODE=1. Repeats CLAUDE_CODE_SAFE_MODE=1.",
                ),
            ),
            (
                "contradictory",
                base.replace(
                    "Sets CLAUDE_CODE_SAFE_MODE=1.",
                    "Sets CLAUDE_CODE_SAFE_MODE=1. Also sets CLAUDE_CODE_SAFE_MODE=2.",
                ),
            ),
            (
                "prefixed-name",
                base.replace(
                    "CLAUDE_CODE_SAFE_MODE=1",
                    "XCLAUDE_CODE_SAFE_MODE=1",
                ),
            ),
        ):
            with self.subTest(label=label):
                with self.assertRaises(capabilities.ClaudeSafetyContractInvalid):
                    capabilities.validate_claude_help(help_text)


if __name__ == "__main__":
    unittest.main()
