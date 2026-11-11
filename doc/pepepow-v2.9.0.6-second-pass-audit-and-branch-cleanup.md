# PEPEPOW Core v2.9.0.6 — Second-pass RC source audit and fork cleanup (2026-11-11)

**Status: DRAFT / NOT RELEASE APPROVAL.** This document is an audit of the candidate, not a test pass for error paths. Official `MattF42/PePe-core:master`, fork `master`, release tags and official assets are not changed here.

## Verified source and CI baseline

- Official and fork `master`: `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- RC base PR #11: `d29b6cc81a9f9e1f62aa089b5780ef698d6c6439`.
- Combined PR #15 HEAD **before this documentation-only commit**: `479de943f0a530a218d10b27b911103958ae5c67`.
- x86_64 [Actions #42864061348](https://github.com/edisontw/PePe-core/actions/runs/42864061348) and native ARM64 [Actions #42864061217](https://github.com/edisontw/PePe-core/actions/runs/42864061217): each build + Ubuntu 22.04 + Ubuntu 24.04 = **3/3 successful jobs**. Both builds checked out the exact same PR HEAD. x86_64 now uploads/verifies an outer archive SHA256; internal package hashes, Qt naming, native headless tools and Xvfb/regtest smoke checks passed.
- These CI runs do **not** cover live mainnet wallet rollback/commit failures, Qt application shutdown during consolidation, or actual Windows RC execution. Older Qt Windows pool-wallet acceptance is from an earlier source and cannot be substituted.

## Re-review: code-grounded risks that need focused acceptance

### P0 — Wallet persistence after mempool acceptance

File: `src/wallet/wallet.cpp`, `CWallet::CommitTransaction` / `AddToWallet`.

- PR #9 changes order to `AcceptToMemoryPool(false)` before `reservekey.KeepKey()` / `AddToWallet()` / wallet notifications; this avoids recording spent inputs when mempool policy rejects the transaction.
- `AddToWallet()` returns `false` on failed `WriteToDisk()`, but `CommitTransaction()` ignores the return. The ignored return is **pre-existing**, not a newly introduced defect; its implications after this ordering change still require review.
- **Do not** assume a bare `return false` after mempool acceptance is a complete rollback: the tx may already be accepted, wallet memory and persistence may disagree, and key reservation/notifications must be reconciled.
- Focused test: disposable regtest wallet, forced mempool rejection and deliberately injected disk write failure; verify transaction state, subsequent send, wallet restart, inputs, notifications and no false retry; check concurrent RPC/GUI and PrivateSend/InstantSend interaction.
- No failure-injection result has yet been produced, so this remains a **release-blocking validation risk**, not a confirmed exploitation.

### P0 — Qt consolidation worker shutdown and wallet lifetime

File: `src/qt/coincontroldialog.cpp`, `ConsolidationBatchWork`.

- Work runs on `QThreadPool::globalInstance()`, captures a raw `CWallet*`, and posts completion to a `QPointer<CoinControlDialog>`. `done()` blocks ordinary dialog close, but that is not proof of safe application shutdown or wallet teardown while a worker is signing/committing.
- Focused test: close entire Qt app during signing, after mempool accept, while completion is queued, and during confirmation wait; verify no use-after-free, thread leak, data loss, repeated send or stuck shutdown. Test with backup/test wallet only.
- Then verify exact outpoints, eligible/excluded coins, <80,000-byte signed size, <=500 candidates, bounded fees, confirmation barrier and pause/restart. No mainnet collateral spend.

### P1 — Masternode Recovery request/reply invariants

File: `src/masternodeman.cpp`, `CMasternodeMan::CheckAndRemove`.

- Current staging source has only five diagnostic `(int)` casts relative to standalone PR #6; 6-of-10 quorum, 24-block ping freshness and signature checks remain. Historical live field logs showed verified reprocessing and stale skips.
- `mMnbRecoveryRequests[itMnbReplies->first]` can insert a default record if a queued reply key is missing (already present before PR #6). Inspect whether request/reply cleanup and restart invariants exclude this condition, rather than changing quorum/cooldown without evidence.
- Focused test: time-aligned comparison of exact masternode outpoints, height/hash and ping on two independent nodes, plus normal request expiry/retry. Keep PR #6 Draft for maintainer review.

### P1 — Build provenance and Windows

- Linux x86_64: one `.tgz` with suffixless `PEPEPOW_qt` (AppImage runtime inside), `bin/PEPEPOWd`, `bin/PEPEPOW-cli`, `bin/PEPEPOW-tx`.
- ARM64: one `.tgz` with native `PEPEPOW_qt`, daemon, CLI, tx and Qt library/plugin bundle. Physical ARM64 desktop remains *untested but owner-waived*, not a PASS claim.
- Windows: build from the final approved exact source and verify Qt startup, backup large wallet, RPC balance parity, regular send, Coin Control, Masternode tier, Send All and error handling. Record PE architecture, DLL imports and SHA256 for every final asset.
- From the approved **final official release commit**, fresh-build all platforms, reconcile Release Notes, verify artifact SHA256, version/release flag and OPTIONAL/MANDATORY classification. No early tag/release.

## Fork cleanup audit

Fork branches at audit: **55 total, 23 `artifacts/*` branches**, 12 Draft PRs before the cleanup. The staging PR #15 includes all 15 source paths from #12, #13 and #14 plus release docs. Both relevant combined Linux CI runs succeeded. No formal reviews existed on these three subordinate PRs. They have been **closed as superseded** (not merged), with audit comments:

| PR | Superseded content | State |
|---|---|---|
| [#12](https://github.com/edisontw/PePe-core/pull/12) | portable Linux x86_64 | Closed, unmerged; #15 replacement |
| [#13](https://github.com/edisontw/PePe-core/pull/13) | native ARM64 desktop | Closed, unmerged; #15 replacement |
| [#14](https://github.com/edisontw/PePe-core/pull/14) | Qt Coin Control presentation/defaults | Closed, unmerged; #15 replacement |

**Keep** open #6, #9, #11, #15 and the other feature PRs required for upstream review. Do not merge subordinate PR #12/#13/#14 into master; their features are already present in #15. Keep their source heads and test artifacts until final release provenance is complete.

### Branch-retirement candidates (identified, NOT deleted)

These three feature branches are **fully behind** fork `master` (comparison: ahead=0), and are candidates for deletion only after confirming no external deployment depends on them:

- `docs/pr38-pr39-win64-acceptance` — behind master by 1.
- `perf/qt-large-wallet` — behind master by 12; PR #2 merged.
- `perf/startup-win-mmap-review` — behind master by 10; PR #3 merged.

**Do not delete yet:** open-PR heads; `release/v2.9.0.6-rc1-*`; `artifacts/*` referenced by draft release evidence; diverged experimental `perf/startup-*`; `realsetvin-patch-*`, `private-send-recalibration`, `Reboot` and any branch with unreviewed unique changes. Earlier Recovery and mmap artifact branch sets can be further deduplicated **after** preserving provenance/reference links; deleting test branches breaks linked downloads. GitHub connector did not provide a branch-ref deletion action for this audit, so no branch refs were removed.

## Publication gate

Current decision: **continue RC testing, NO-GO for official v2.9.0.6 Release** until #6/#9 security and wallet acceptance, Windows runtime/build, upstream maintainer sign-off and final source-based artifacts are complete. No force-push, master merge, tag or release was performed.
