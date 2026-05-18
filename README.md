# Codex Review Workflows

Public Codex review orchestration, PR readiness, and local delivery gate skills.

## Test

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/* skills/external-review-playbook/scripts/* skills/pr-readiness-review-workflow/agents/openai.yaml
python3 -m unittest discover -s skills/external-review-playbook/tests
```
