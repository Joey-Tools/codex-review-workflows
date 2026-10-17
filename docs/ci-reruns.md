# CI Diagnostic Reruns

For a user-requested retry or an authorized CI-fix loop, follow the playbook's
[ordinary diagnostic rerun guidance](../skills/review-orchestration-playbook/references/github-codex-producer-and-recovery.md#ordinary-diagnostic-reruns).
It separates disposable-runner tests/read-only validation from operations with
publication, deployment or other external write effects.

This repository's CI runs platform, broker and supervisor tests on GitHub-hosted
runners with `contents: read`. Inspect the exact executed workflow, relevant
candidate code and follow-on effects before choosing a rerun; that permission
setting alone does not prove repeat safety.

An upstream dependency fix is a valid diagnostic reason. Check the reference
and resolved version, choose failed-job versus full rerun accordingly, and use
GitHub run/attempt history and logs rather than maintaining a second ledger.
There is no repository-specific workflow-digest contract or attempt-2 ceiling.

CI retries do not waive review, execution approval or merge rules. Machine
producer evidence and authoritative automatic provider recovery retain their
separate playbook contracts.
