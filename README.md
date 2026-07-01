# Codex Review Workflows

Public review orchestration and local delivery gate skills.

`review-orchestration-playbook` is the single entrypoint for pinned local Codex review, Claude-family double review, GitHub Codex triple review, and PR readiness.

## Test

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -m unittest discover -s skills/review-orchestration-playbook/tests
```
