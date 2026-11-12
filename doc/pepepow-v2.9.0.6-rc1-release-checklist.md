# PEPEPOW Core v2.9.0.6 — RC release checklist

**Status:** Final-scope Optional v2.9.0.6 candidate; still Draft, not merged to official `MattF42/PePe-core`, tagged or released. Owner approved inclusion of A+B+C and deferred extra edge testing to after release. Production compilation and native Windows acceptance have not been completed.

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

## Final feature scope (Owner decision 2026-11-11)

- [x] **A / Wallet persistence:** include the preliminary error-reporting mitigation (on failed `AddToWallet`, warn with txid; never claim RPC/Qt success, no blind retry). It does **not** make DB/mempool writes atomic. Owner defers additional live failure testing until after release.
- [x] **B / Qt consolidation shutdown:** include the dedicated worker-pool/drain patch from experimental PR #16. Its four controlled post-fix shutdown windows passed; no further B tests requested before release.
- [x] **C / Recovery orphan replies:** include the small `find()` guard from PR #16; 22/22 assertions passed. No further C tests requested.
- [x] Declare **v2.9.0.6 Optional Upgrade** (no intentional consensus or protocol change; maintainers still review this classification).
- [x] ARM64 physical Qt desktop test waived; no PASS claim.
- [ ] **Build environment:** recover GitHub Actions Docker dependency network/DNS; candidate x86_64/ARM64 runs #43045018093/#43045018025 failed *before C++ compilation*, not due to source errors.
- [ ] Compile/review the exact selected A+B+C candidate on Linux x86_64 and native ARM64, with existing build smoke tests and per-archive SHA256.
- [ ] Compile Windows x86_64 Qt/daemon/CLI/tx from the selected candidate; Owner tests the *exact resulting Windows package* **before official Release**, after final compilation.
- [ ] Submit one final reviewed candidate to MattF42 and receive maintainer approval/merge; no direct upstream master changes or force-push.
- [ ] After official source SHA is approved, rebuild **all three release assets** from that exact SHA; confirm `_CLIENT_VERSION_IS_RELEASE` is set only at the publishing stage, verify `OPTIONAL` classification, generate SHA256, and publish tag/Release only with maintainer authorization.

## Current source

- Official and fork `master`: `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- RC base: [PR #11](https://github.com/edisontw/PePe-core/pull/11).
- Combined platform/UI candidate: [PR #15](https://github.com/edisontw/PePe-core/pull/15) (its current HEAD must be rechecked, not copied from this document).
- The candidate for final A+B+C inclusion is `release/v2.9.0.6-rc2-optional-candidate`, directly based on PR #17's A-only version; PR #16 only supplied reviewed B/C code and test evidence, not an unreviewed whole-PR merge.
- #12, #13 and #14 closed **as superseded**, not merged; the combined source lives in #15.

[Draft public release notes](release-notes/pepepow-v2.9.0.6-draft.md) · [Detailed engineering/agent audit](pepepow-v2.9.0.6-second-pass-audit-and-branch-cleanup.md)

> This checklist is intended for human maintainers. Source-level failure modes and historical test logs remain in the technical audit. The Owner explicitly accepted deferred edge testing; release still requires successful exact-source compilation, Windows acceptance, maintainer review and verified assets.