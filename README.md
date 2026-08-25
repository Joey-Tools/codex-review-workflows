# Codex Review Workflows

This repository publishes Joey's review and delivery skills. The main entrypoint is
[`review-orchestration-playbook`](skills/review-orchestration-playbook/SKILL.md),
which coordinates fresh local review, optional Claude Code review, GitHub Codex,
and PR readiness without duplicating those contracts across every caller.

## Review Shapes

| Request | Review processors | Notes |
| --- | --- | --- |
| Single | One fresh-context local Codex review session | The orchestrator may use either the reviewer subagent adapter or the Codex CLI adapter. |
| Double | Single plus one independent Claude Code review | Claude is opt-in and reviews the same frozen committed range in a separate clean workspace. |
| Triple | Double plus current-head GitHub Codex | Requires an eligible existing `github.com` PR and accepted provider evidence. |
| `skill-repo-codex-gate` | One fresh local Codex review plus current-head GitHub Codex | Non-named default for the configured Joey-Tools skill repositories; it never adds Claude implicitly. |

Each named local processor gets its own independent, clean Git workspace and
reviews a frozen `base_sha..head_sha`. A named shape selects logical review
sessions, not the number of internal workers a high-reasoning model may use.

## Included Skills

- [`review-orchestration-playbook`](skills/review-orchestration-playbook/SKILL.md)
  owns named review shapes, PR readiness, retry/recovery, and result reporting.
- [`change-delivery-workflow`](skills/change-delivery-workflow/SKILL.md) owns the
  local implementation, validation, documentation, review-handoff, and commit
  gate.
- [`agile-delivery-workflow`](skills/agile-delivery-workflow/SKILL.md) delivers an
  explicitly requested early usable slice before the normal delivery gate.
- [`synthetic-token-fixtures`](skills/synthetic-token-fixtures/SKILL.md) selects
  exact catalogued synthetic credentials for fixtures that must pass secret
  admission.

## Review Resource Map

- [Local Codex lane](skills/review-orchestration-playbook/references/local-codex-lane.md):
  peer subagent/CLI adapters, capability selection, prompt, and findings contract.
- [Review workspace](skills/review-orchestration-playbook/references/review-workspace.md):
  independent clean-workspace preparation, validation, cleanup, and incomplete-range guidance.
- [Claude Code lane](skills/review-orchestration-playbook/references/canonical-claude-lane.md):
  runtime and output validation for the optional Claude processor.
- [GitHub Codex evidence authority](skills/review-orchestration-playbook/references/github-codex-evidence-authority.md):
  provider identity, current-head result classification, and unresolved-finding rules.
- [PR readiness](skills/review-orchestration-playbook/references/pr-readiness.md):
  branch, lifecycle, CI, and conversation gates around the requested review shape.
- [`named_lane_guard`](skills/review-orchestration-playbook/scripts/named_lane_guard):
  public clean-workspace and validated Claude runtime command surface.

## Development

The helper requires Python 3.10 or later; CI pins the minimum supported runtime.
From the repository root, run:

```bash
python3 -B -c 'import pathlib, sys; [compile(pathlib.Path(path).read_bytes(), path, "exec") for path in sys.argv[1:]]' skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/named_lane_guard skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -B -m unittest discover -s skills/review-orchestration-playbook/tests
bash -n skills/review-orchestration-playbook/scripts/build_claude_keychain_broker_macos.sh
bash -n skills/review-orchestration-playbook/scripts/install_claude_keychain_broker_macos.sh
```

Validate changed skill metadata with the installed skill-authoring validator
before committing. Keep policy in `SKILL.md` and its routed references rather
than expanding this human overview.
