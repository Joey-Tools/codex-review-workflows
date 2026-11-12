---
id: 20261112-large-checkout-capacity
title: Bounded review capacity for large tracked checkouts
status: completed
created: 2026-11-12
updated: 2026-11-12
branch: wip/hdr-large-checkout-capacity-20261112
pr:
supersedes: []
superseded_by:
---

# Bounded review capacity for large tracked checkouts

A repository with more than 100,000 small tracked entries could fit the existing
object, checkout-byte, path-byte and pack budgets but fail before a review
workspace was created. The workspace and materializer entry ceilings now both
allow 200,000 entries. Existing source custody, clean-index, symlink and byte
limits continue to apply independently, with unchanged receipt schemas.

Synthetic metadata tests exercise 100,001 and 200,000 entries successfully and
reject 200,001. They create no large filesystem tree. The same tests reproduced
the prior rejection before the two-constant fix. Six targeted checkout,
materializer, index and byte-budget tests pass after it, together with the
existing materializer hard-cap test and its seven rejection cases. A real
larger-checkout engineering preparation also completed with the other bounds
unchanged.

The materializer's exact path-output envelope remains derived from the entry
ceiling and object-id width. Its regression assertions bind 78,308,864 bytes
for SHA-1 and 83,108,864 bytes for SHA-256; the targeted envelope and existing
hard-cap tests pass with those expectations.

The change adjusts finite capacity only. It does not waive review, change
receipt schemas, bypass clean-workspace checks or execute checked-out sources.
