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

- [ ] **A wallet persistence:** [isolated A-only fix PR](https://github.com/edisontw/PePe-core/pulls) must pass actual Regtest failure-injection and normal-send/rejection/restart checks, then receive maintainer review. An RPC false-success **was reproduced** in PR #16; the candidate fix prevents false success but does not make mempool and wallet DB atomic.
- [ ] **Qt shutdown finding (B):** controlled test of original consolidation worker reproduced shutdown aborts; PR #16's corrective worker drain passed four cases. Owner has stopped further B/C *testing*, but must choose whether to include the already-tested B fix or defer the affected consolidation feature (#9). Do not silently treat a known crash as resolved when B code is omitted.
- [ ] **C Recovery orphan reply guard:** test-only finding; no extra C testing requested; owner/maintainer may defer the guard without changing quorum. #6's other Recovery changes still need maintainer review.
- [ ] Build **pre-merge candidate** Windows x86_64 Qt/daemon/CLI/tx and validate pool-wallet startup, balance, send and UI functions using a backed-up wallet copy. Linux exact-candidate builds should also be green.
- [ ] Confirm exact release contents and optional/non-consensus classification against final diff.
- [ ] Submit the reviewed final candidate to `MattF42/PePe-core` for the maintainer's approval and normal merge. Do not force-push or directly modify either master. Keep `_CLIENT_VERSION_IS_RELEASE=false` for candidate builds.
- [ ] **After official merge / exact release commit:** set or verify final release flag, rebuild Windows x86_64, Linux x86_64 and Linux ARM64 from *that exact approved SHA*, validate extracted binaries and publish per-archive SHA256 and the optional v2.9.0.6 Release.

## Current source

- Official and fork `master`: `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- RC base: [PR #11](https://github.com/edisontw/PePe-core/pull/11).
- Combined platform/UI candidate: [PR #15](https://github.com/edisontw/PePe-core/pull/15) (its current HEAD must be rechecked, not copied from this document).
- A failure-path patch: standalone branch `fix/rc-wallet-persistence-A-only`, based on PR #15 and intentionally **excluding B/C**. It is not yet accepted or merged. PR #16 is experimental evidence, not a release integration source.
- #12, #13 and #14 closed **as superseded**, not merged; the combined source lives in #15.

[Draft public release notes](release-notes/pepepow-v2.9.0.6-draft.md) · [Detailed engineering/agent audit](pepepow-v2.9.0.6-second-pass-audit-and-branch-cleanup.md)

> This checklist is intended for human maintainers. Engineering failure-injection procedures, source-level risks and historic commit data live in the linked technical audit. No additional broad retesting is required without a source change.