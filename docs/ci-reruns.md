# Manual CI Diagnostic Reruns

This repository predeclares **reentrant**, not result-idempotent, execution for
the exact CI workflow bound by
[`ci-rerun-contract.json`](../.github/ci-rerun-contract.json). Reentrant means
repeating a failed test job on a fresh GitHub-hosted runner does not depend on
the previous runner's mutable state or repeat a publication or repository write.
It does not promise identical results, prove a failure transient, or authorize a
retry. Hosted images, package repositories, and tool downloads remain external
inputs under the ordinary CI trust boundary; this is not an immutable producer
closure or a deterministic-build claim.

## Scope and repeat-safety basis

Only `existing-run-rerun-failed-jobs` for
`Joey-Tools/codex-review-workflows/.github/workflows/ci.yml` is declared.
GitHub can rerun failed jobs and their dependent jobs, including the aggregate
`test` job; it is not a single-test selector.

| Job | Repeat-safety basis | Per-job limit |
| --- | --- | --- |
| `platform_tests` | Fresh checkout and runner-local Python, packages, Linux isolation settings, and test fixtures; no shared cache or publication. | 60 minutes, two matrix legs |
| `broker_reproducibility` | Rebuild/check tracked broker bytes on a fresh macOS runner; no artifact or release upload. | 15 minutes |
| `independent_supervisor_tests` | Test runtime and subprocess fixtures are local to the runner; no GitHub producer request. | 15 minutes |
| `readonly_install_supervisor_tests` | A fresh root-owned isolation directory, uv cache disabled, and a runner-local user/group; cleanup or retained-path failure stays a failure. A new runner does not reuse that state. | 20 minutes |
| `test` | Reads dependency results and exits nonzero unless every required leaf succeeds. | 5 minutes |

All jobs use GitHub-hosted runners. Workflow permissions are `contents: read`;
checkout credentials are not persisted, checkout binds `github.sha`, and
external Action selectors are full commit SHAs. No job dispatches workflows,
posts comments/reviews, pushes commits, deploys, uploads releases, or publishes
shared artifacts. Test-controlled local Git, process, and filesystem mutations
are confined to the disposable runner. Existing runtime custody, signal,
cleanup, source-only, test-selection, and aggregate-pass gates remain unchanged.
This contract does not grant candidate tests secrets or additional permissions.

## Independent trust and exact-workflow binding

Use the declaration only after it has been independently reviewed and merged
into the trusted default branch. A candidate's own declaration, checker, or
passing CI cannot approve itself. Read the trusted policy and declaration from
outside the candidate range; obtain the executed workflow bytes at the
platform-authenticated workflow commit, not from today's branch tip. Require
their SHA-256 to equal the trusted declaration's `workflow_sha256`. Preserve
that provenance with the run receipt.

Each test-producing leaf job records only run ID/attempt, workflow SHA/ref, and
execution SHA/ref in its first step, before checkout or candidate code. Acquire that exact step
through authenticated job logs and join it to the run/attempt/job API records;
do not accept a similarly worded line printed later by a test. Missing or
contradictory identity evidence stops preflight. These are provenance hints
under the ordinary hosted-runner trust boundary, not signed attestations or
an override of the independently trusted workflow-byte check.

The local checker detects schema or byte drift; it does not prove the
side-effect audit, collect authenticated evidence, grant authorization, or
implement a POST:

```bash
python3 -B .github/scripts/check_ci_rerun_contract.py
python3 -B -m unittest discover -s .github/tests -p 'test_*.py' -v
```

When workflow bytes change, re-audit the complete jobs and dependencies, update
the declaration and reviewed canonical CI fixture in the same PR, and obtain
independent review again. Updating a digest alone is not a safety review.
An older run with different workflow bytes, floating Action tags, or no
matching trusted declaration is **not retroactively covered**. In particular,
this change does not authorize retrying model-profile PR #119's old CI run
38552908494. A separately authorized base refresh creates a new head/run and
invalidates old-head review and readiness evidence.

## Operator preflight and one-shot transaction

These are mandatory operator checks, not functionality supplied by the checker.
Before requesting execution approval:

1. Hold one mutation owner for the exact repository/run. Obtain separate
   current-task authorization for this exact failed-jobs rerun, naming the PR,
   full head SHA, run ID, observed attempt, reason, and cost scope. Ordinary
   delivery consent or this declaration alone is insufficient.
2. Acquire fresh authenticated PR, workflow, run, attempt, and complete job
   records. Require an open same-repository PR targeting `master`, its exact
   current full head, and a `pull_request` run for that PR/head. Independently
   verify the event's synthetic merge execution SHA/ref and workflow SHA; do
   not equate the API's feature `head_sha` with `GITHUB_SHA`. Require the
   exact workflow byte binding above and record the run/workflow/check identity.
   Audit the scripts/tests at that exact candidate head against the declared
   runner-local effect boundary as well: the workflow digest does not bind
   candidate dependency bytes. A changed dependency that adds external writes,
   publication, shared mutable state, secrets, or unproved repeat safety stops
   preflight even when the workflow digest still matches.
3. Require `completed/failure` at attempt **1**, with no newer run for the
   same PR/head and no in-flight recovery. Inspect every failed job and its
   dependent closure against the declared jobs. Abort on unknown jobs,
   incomplete evidence, identity drift, or an unexplained safety/cleanup
   failure. A test failure is not an infrastructure classification: an
   explicitly requested diagnostic may investigate it only after its cause
   and side-effect safety have been assessed; the rerun does not erase it.
4. Acquire execution approval, then reread PR/head/run/attempt immediately
   before one bodyless POST to the exact run's `/rerun-failed-jobs` endpoint,
   under GitHub API version `2026-03-10`. Do not use full rerun, debug logging,
   workflow dispatch, another workflow, a review request, an empty commit, or
   another transport to bypass a rejected operation. A read-then-POST race
   remains; GitHub does not provide an atomic PR-head compare here.
5. Retain the HTTP response and timing. An HTTP 201 is request acceptance,
   not test success. An ambiguous POST consumes this one-shot authorization:
   stay read-only, inspect status, and do not repeat it. Require an authenticated
   attempt-2 receipt linked to attempt 1 and a current-run receipt with the
   same run/head/workflow/ref and `run_attempt == 2`. Unexpected attempts or
   identity changes are inconclusive, not permission to try again.
6. Wait read-only for terminal attempt 2 and inspect all jobs, required checks,
   and retained failure evidence. Stop on repeated failure, cleanup uncertainty,
   superseded head, or PR closure. Maximum attempt 2 permits only **one** rerun
   of a run; a new run does not silently replenish an authorization budget.
   No automatic loop, concurrent retry, or repeated rerun is authorized.

## Authority boundary

This is a repository-specific **manual diagnostic** repeat-safety declaration.
It changes no branch protection, ruleset, required check, review lane, or
finding-resolution rule. A later successful CI attempt is fresh test evidence,
not proof of root cause and not permission to ignore an applicable finding.
Current-head CI, review, conversations, and merge gates remain separate.

It does not satisfy the playbook's
[`github-codex-recovery-operation-preflight-v1`](../skills/review-orchestration-playbook/references/github-codex-producer-and-recovery.md)
automatic provider-recovery contract. Complete outside-candidate trust,
immutable implementation/dependency closure, machine-retryable reason,
exact transaction receipts, and independent current mutation authorization are
still required there. Code, test, or policy failures must not be relabelled as
infrastructure. Installation of this document does not change execution
environment policy or overturn a prior approval denial.

## Platform references

- [GitHub rerun semantics](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs):
  reruns retain the original event's SHA/ref and original actor privileges.
- [GitHub Actions run API](https://docs.github.com/en/rest/actions/workflow-runs?apiVersion=2026-03-10#re-run-failed-jobs-from-a-workflow-run):
  exact failed-jobs endpoint and HTTP acceptance semantics.
- [GitHub workflow identity variables](https://docs.github.com/en/actions/reference/workflows-and-actions/variables):
  the runner-provided workflow and execution SHA/ref fields logged by CI.
