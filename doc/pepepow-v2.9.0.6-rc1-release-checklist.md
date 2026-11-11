# PEPEPOW Core v2.9.0.6 — RC release checklist

**Status:** Draft; not merged to official `MattF42/PePe-core`, tagged or released.

## What is ready?

| Component | Evidence | Status |
|---|---|---|
| Linux x86_64 | [CI: build + Ubuntu 22.04/24.04](https://github.com/edisontw/PePe-core/actions/runs/42864061348); Owner tested daemon, CLI, Qt and transaction sending | PASS for RC |
| Linux ARM64 | [Native CI: build + Ubuntu 22.04/24.04](https://github.com/edisontw/PePe-core/actions/runs/42864061217); four real ARM64 masternodes have remained operational | PASS for RC |
| Masternode Recovery | Owner reports ENABLED **45 locally / 47 on four other nodes**, following another day of use; no new reported regression | Field observation; no critical regression reported |
| UTXO consolidation | Owner confirmed **interruption and restart have already been tested** | PASS for that scenario; do not repeat |
| Windows x86_64 | Earlier Qt large-wallet fix verified on Windows, but final combined RC not yet built and tested there | PENDING |
| ARM64 physical desktop | No real desktop GUI test; Owner explicitly waived this requirement | Accepted limitation, not a PASS claim |

Both Linux archives contain Qt (`PEPEPOW_qt`), daemon, CLI and tx in **one `.tgz` per platform**. The CI checks archives and SHA256; final release hashes must be generated from *final official source*.

## Decisions before official v2.9.0.6

- [ ] Obtain maintainer review of #6 Recovery and #9 wallet commit/error handling. No new issue has been reproduced; remaining checks are failure-path/edge-case reviews.
- [ ] Validate final combined Windows x86_64 Qt/daemon/CLI/tx, pool-wallet balance, send and UI functions.
- [ ] Confirm exact release contents and optional/non-consensus classification against final diff.
- [ ] Merge through normal upstream PR **only with authorization**; set release flag/tag only at publication stage.
- [ ] Rebuild Windows x86_64, Linux x86_64 and Linux ARM64 from approved upstream release commit, inspect each package and publish true SHA256 checksums.

## Current source

- Official and fork `master`: `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- RC base: [PR #11](https://github.com/edisontw/PePe-core/pull/11).
- Combined platform/UI candidate: [PR #15](https://github.com/edisontw/PePe-core/pull/15) (its current HEAD must be rechecked, not copied from this document).
- #12, #13 and #14 closed **as superseded**, not merged; the combined source lives in #15.

[Draft public release notes](release-notes/pepepow-v2.9.0.6-draft.md) · [Detailed engineering/agent audit](pepepow-v2.9.0.6-second-pass-audit-and-branch-cleanup.md)

> This checklist is intended for human maintainers. Engineering failure-injection procedures, source-level risks and historic commit data live in the linked technical audit. No additional broad retesting is required without a source change.