---
id: 20260730-hbp001
title: Hosted Broker Codesign Pin
status: completed
created: 2026-07-30
updated: 2026-08-01
branch: wip/broker-codesign-pin-refresh
pr: https://github.com/Joey-Tools/codex-review-workflows/pull/85
supersedes: []
superseded_by:
---

# Hosted Broker Codesign Pin

## Summary

- Keep broker reproducibility fail closed while GitHub rolls macOS runners from
  macOS 26.4 to 26.5.2.
- Select the reviewed host `codesign` digest by exact OS version and build.
- Emit the observed SHA-256 for every verified broker build input so future
  runner drift is directly auditable.
- Select the hosted no-child blocker profile from the exact reviewed
  OS/build/Darwin/Python catalog instead of pinning the workflow to one runner
  generation.

## Current State

- Hosted macOS 26.4 build `25E246` accepts only
  `06eacc36d43376972d3bca0a2137ea4efd6d0fe27de8a7af0e6b11d599e8f337`.
- Hosted macOS 26.5.2 build `25F84` accepts only
  `214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7`.
- Any other hosted OS version/build remains blocked before the broker is built.
- Hosted no-child fail-closed probing accepts only the exact reviewed
  macOS 26.4 build `25E246` or macOS 26.5.2 build `25F84` runtime fingerprint;
  an unknown runtime fails before the probe.
- Source, artifact, Xcode, SDK, clang, linker, lipo, vtool, and
  `codesign_allocate` pins are unchanged.
- Hosted read-only execution enters the source-only gate through bounded stdin
  under `-I -B -S`; the candidate path is never the Python entrypoint. Its
  root-owned staged source uses a bounded descriptor manifest and copy rather
  than an unbounded recursive copy. The source receipt retains root ownership
  and source access policy, while the installed tree independently requires the
  exact receipt-bound ephemeral execution UID and GID plus an
  execution-identity-projected expected manifest. Account creation, launch,
  postrun closure, and cleanup remain bound to the same user/group GUIDs and
  exact-UID process census; the shared system `nobody` account is no longer a
  supported hosted execution identity. The hidden-account policy is bound to
  the exact native Directory Services attribute
  `dsAttrTypeNative:IsHidden: 1`; every account check reports a controlled
  property-specific reason plus shell-escaped expected and observed values
  before retaining an unproved record.

## Next Steps

- None in this repository. The private overlay sync publishes this catalog with
  the rest of the reviewed control plane.

## Evidence

- Private overlay PR #139 job `90795685398` ran on image
  `20260728.0273.1` and isolated the drift to `/usr/bin/codesign`; every earlier
  fixed input passed.
- Canonical PR #85 job `90798189131` passed on image `20260720.0258.1`,
  proving the legacy OS build and digest remain active during rollout.
- Canonical PR #85 rerun job `90800935103` ran on image
  `20260728.0273.1` and reported the exact new digest before failing closed.
- Fresh Codex review found that the independent-supervisor job still selected
  only the legacy 26.4 no-child profile while the broker job had admitted
  26.5.2.
- Canonical PR #85 rerun job `90814780194` then ran on macOS 26.5.2 build
  `25F84`, Darwin `25.5.0`, with `/usr/bin/sandbox-exec` SHA-256
  `8290e4be7387a0df83cd1559e86afd880464f269450573d012795761fe298f16`,
  proving the legacy-only workflow failed closed on the new runner generation.
- Local `--developer-check` reproduced the pinned broker artifact exactly with
  the unchanged source, toolchain, signing identity, and CDHashes.
- `Claude lane temporarily waived by Joey before 2026-08-01 00:00 Asia/Shanghai`;
  the unrun lane is not counted as a completed named double or triple.
- A fresh control review found that shell size/digest predicates could fall
  through and that installed-release validation reopened the gate path for
  execution. The corrected runbook exits explicitly on every predicate failure
  and uses parent-validated Python to read one no-follow descriptor, validate
  the manifest digest over those exact bytes, and stream that same memory image
  to the isolated gate. The executable regression accepts the bound input and
  rejects digest mismatch, oversize, symlink, hard-link, and FIFO inputs before
  any candidate byte reaches the consumer. Frozen Git size and digest producer
  failures also terminate before the gate pipeline.
- The canonical/fixture hosted workflows remain byte-for-byte aligned after
  moving the outer gate to stdin. Private overlay synchronization and release
  are owned by the separate BL workstream; this canonical follow-up does not
  modify or trigger private PR #139 or #140.
- Canonical PR #86 job `91434745317` proved the first bounded-copy revision
  incorrectly compared the nobody-owned destination with the root source UID.
  It failed before child launch with complete cleanup and no retained paths.
  The follow-up keeps the two ownership policies separate and adds a synthetic
  root-to-nobody acceptance plus wrong-destination-owner rejection regression.
- A final hosted-consumer audit also found that the new nonempty source manifest
  conflicted with the previous null-only parser contract and that printing the
  raw summary before validation could expose attacker-controlled bytes. The
  canonical workflow and both fixtures now accept only an exact lowercase
  SHA-256, bind it into the closed expected summary, suppress raw output, and
  print canonical JSON only after validation. The executable contract rejects
  missing, null, short, uppercase, non-hex, and sentinel-bearing inputs without
  echoing the sentinel. The final audit returned `No findings.`; contracts
  passed 105/105 and full Python 3.13.12 discovery passed 2,833/2,833 in
  1008.735 seconds with six platform skips.
- Fresh prior-bundle Codex review of the resulting signed head found two
  additional protected-property gaps. The outer Trusted Mac gate did not bind
  every compiled module and fixture to exact committed content, Git mode, and
  inventory, while the hosted root-to-nobody copy still depended on ambient
  filesystem group inheritance. The replacement uses an externally
  digest-bound checked source manifest before any compile or execution and
  derives both destination UID and GID from the held install-container policy.
  Source owner and access-policy evidence remain independent. The affected
  runner passed 145/145 in 54.773 seconds, and the host-level deterministic
  selection passed 839/839 in 241.339 seconds with selected-identity SHA-256
  `7eae7f29771b98d6ddef11365c2896b25f8a216b80d168464ffe5dec8e0b73fd`.
- The complete P1-corrected host-level Python 3.13.12 discovery passed
  2,833/2,833 tests in 941.501 seconds with six existing platform skips;
  repository contracts passed 105/105 in 8.167 seconds.
- PR #86 run `30730882541` attempt 1 passed all 839 child tests but failed
  closed with `ChildProcessTreeClosureUnproven` for
  `8608:1785641827.600459/state=2`. The hosted workflow repeatedly used the
  shared system `nobody` UID, so an empty baseline did not prove exclusive
  ownership for the duration of the job. Attempt 2 job `91453660059` passed with
  proven closure and complete cleanup, but remains retry evidence rather than a
  refutation of the account-selection defect.
- The canonical workflow and both reviewed fixtures now use a randomly named,
  GUID-bound ephemeral non-admin account with a dedicated unused UID/GID.
  Creation, prelaunch use, postrun closure, and deletion are bound to the same
  user/group receipts and exact-UID process census. Any identity ambiguity,
  replacement, census failure, or residual process fails closed and retains the
  records until the ephemeral hosted runner is disposed; no shared `nobody`
  process can contaminate the dedicated UID census.
- PR #86 exact-head run `30734590280`, job `91460962452`, created
  `codexreviewb4aed91925e3` with UID/GID `56254` but failed before supervisor
  launch because the workflow expected the display string `IsHidden: 1`.
  macOS exposes that native record as `dsAttrTypeNative:IsHidden: 1`, including
  when queried through the short attribute name. The replacement creates and
  reads the full native attribute, keeps exact scalar comparison, rejects the
  short name, `YES`, empty, and multi-record forms in an executable parser
  contract, and emits the first failing property before retaining the user and
  group. It does not add a retry, change `RealName`, or weaken any identity or
  non-admin assertion. The GitHub annotation is fixed text; dynamic diagnostics
  use `printf '%s\n'` on a separate ordinary line, and an executable Bash 3.2
  `xpg_echo` regression proves an observed newline followed by
  `::warning::...` cannot become a second workflow command.
- The superseding account-verifier head reached the deterministic suite in PR
  #86 run `30736565697`, job `91466273221`, but a fixture
  `/usr/bin/git init` exceeded its existing 10-second deadline. The fixture used
  `subprocess.run`, whose timeout path did not establish descendant process-tree
  closure; the outer supervisor correctly reported six same-UID `state=2`
  processes, retained both bound runtime leaves and the ephemeral account, and
  failed closed. All five raw process launches in `test_git_checkout.py` now
  share the production `gitraw.run_bounded` fresh-session process-group owner,
  bounded output, timeout termination, leader reap, and typed
  `GitProcessClosureUnproven` fallback. The 10- and 30-second command deadlines
  remain unchanged. A real fake-Git timeout regression observes a live
  same-group descendant and proves both processes and the group are gone before
  the helper returns; the deterministic selection advances from 839 to 840 with
  reviewed identity digest `6d40334cf49865b44402c49233a9f820b722eb9cb5f35de646f42194b6345fa0`.
  After synchronizing the exact Trusted Mac source manifest, the final
  host-level Python 3.13.12 deterministic gate passed 840/840 in 269.450
  seconds. The earlier manifest-mismatch run is non-counting.
