# Codex Review Workflows

Public review orchestration and local delivery gate skills.

`review-orchestration-playbook` is the single entrypoint for policy-bound local Codex review, Claude-family double review, GitHub Codex triple review, and PR readiness. Claude Code model selection remains pinned, while CLI compatibility follows a publisher-verified release range and explicit macOS, Linux, and WSL2 capability contract documented in [Claude Runtime Trust And Platform Capabilities](skills/review-orchestration-playbook/references/claude-runtime-trust.md).

Publisher verification means the fixed Anthropic signing key, signed per-version manifest, and matching binary checksum; native Mach-O/ELF checks only reject wrappers and incompatible platform artifacts. Before that verification, the candidate's self-reported version runs with a fixed credential-free environment that does not inherit proxy URLs, custom CA paths, authentication material, or review metadata. After verification, the helper copies the candidate into a private, checksum-keyed executable snapshot. Every model attempt reuses only that snapshot for capability probes, post-provenance dependency inspection, credentials, review data, and the final Claude process.

The fixed-path native GPG source is a separately validated host-trust dependency, not evidence of Anthropic publisher provenance. The helper holds its stable file descriptor, copies it into a fresh current-user `0700` home below a trusted `/tmp`, publishes that copy as a `0500` execution snapshot, and uses the snapshot for all key conversion, fingerprint listing, and signature-verification calls. Security-sensitive host tools receive fixed minimal environments rather than inherited loader, shell, or compiler controls. WSL2 support uses multiple positive host signals, including custom-kernel-compatible runtime markers, and bounded `/proc/self/mountinfo` provenance checks; Windows-backed DrvFS paths are rejected even when mounted through a custom automount, bind mount, or alias rather than the literal `/mnt/<drive>` spelling.

Linux and WSL2 use a separate inner file-tool boundary because the trusted Claude runtime must read either its staged `/config` credential or an API key while model-invoked tools must not. The helper uses `dontAsk`, exposes only `Read`, allows only `Read(./**)`, rejects file-mention syntax in the review prompt, and denies every non-workspace synthetic-root mount with absolute double-slash rules such as `Read(//config/**)` and `Read(//proc/**)`. Command construction fails closed if a future mount lacks deny coverage or is added below `/workspace`. The outer `bubblewrap` sandbox still enforces host filesystem, process, write, and network isolation; a read-only credential mount alone is not a confidentiality boundary from the Claude process that authenticates with it.

## Test

The helper requires Python 3.10 or later; CI pins the minimum supported runtime.

```bash
python3 -m py_compile skills/review-orchestration-playbook/scripts/isolated_review skills/review-orchestration-playbook/scripts/review_runtime/*.py
python3 -m unittest discover -s skills/review-orchestration-playbook/tests
```
