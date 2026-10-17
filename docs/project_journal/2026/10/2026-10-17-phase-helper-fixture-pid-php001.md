---
id: 20261017-php001
title: Accessible Supervisor PID Reuse Fixture
status: completed
created: 2026-10-17
updated: 2026-10-17
branch: codex/fix-phase-helper-fixture-pid
pr:
supersedes: []
superseded_by:
---

# Accessible Supervisor PID Reuse Fixture

The final-result CLI fixture uses the live test process's PID with a deliberately
different start identity to model a former supervisor whose PID was reused.
It no longer assumes that an arbitrary fixed PID is absent or accessible;
that assumption caused phase-helper permission failures when the PID belonged
to a system process on macOS.

A regression test verifies that the fixture binds the current process and that
its recorded former identity differs from the observed process-start identity.
The existing final-result lifecycle test still exercises release, final-result
readback and rejection of modified sealed content through the real helper.
Production process-identity, liveness and authorization checks are unchanged.
