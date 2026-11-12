---
id: 20261112-hosted-macos-26-7-2-ci-identity
title: Exact hosted macOS 26.7.2 CI identity
status: completed
created: 2026-11-12
updated: 2026-11-12
branch: wip/hdr-large-checkout-capacity-20261112
pr: 150
supersedes: []
superseded_by:
---

# Exact hosted macOS 26.7.2 CI identity

The GitHub `macos-26` image reported macOS 26.7.2, build 25G332,
Darwin 25.6.0 and sandbox-exec SHA-256
`449b1b7456d11ca74b653edf1785c7a912393ae7192fb99cca5806943f75d872`.
The required no-child and broker jobs refused this unrecognized exact identity.

The hosted test catalog adds that precise tuple alongside all older entries.
Selector regressions reject a different build, Darwin release or Python minor.
The production runtime pin is unchanged. The broker OS selector admits the
same exact hosted OS/build while retaining its source, tool and artifact pins
and complete byte-for-byte reproduction requirement. An observed tool change
must have its own exact reviewed digest; unknown environments remain refused.

Local Python 3.13 validation passed all 59 deterministic no-child unit tests
and four broker artifact/native-identity/build-contract tests. The modified
shell script passed `bash -n`; shellcheck was unavailable on the authoring host.
Required hosted live checks and binary reproduction remain release gates.

The first actual hosted run verified the broker source, tracked artifact and
compiler/linker tool hashes, then refused the changed codesign binary.
Pin its observed SHA-256 `b0fe72653748587b7db6cf5e40f81ae79bcdf424bd1aa11534c4a919cec8d4da` only for the exact new OS tuple.
The original profiles and expected broker output stay unchanged.
Evidence: [hosted reproducibility job](https://github.com/Joey-Tools/codex-review-workflows/actions/runs/43263990460/job/131342500995).
