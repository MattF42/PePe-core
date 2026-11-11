# PEPEPOW Core v2.9.0.6 — INTERNAL engineering audit / AI handoff

**Audience:** developer, reviewer and coding agents, **not** the public-facing PR description. Historical source-level findings here are observations, not demonstrated exploits.

## Authoritative sources

- Fork master and official master verified 2026-11-11: `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- RC integration PR #11 baseline: `d29b6cc81a9f9e1f62aa089b5780ef698d6c6439`.
- PR #15 completed x86_64/ARM64 3/3 CI at exact code SHA `479de943f0a530a218d10b27b911103958ae5c67`; later documentation commits do not change Core/Qt code. Recheck live HEAD.
- Linux x86_64 [Actions 42864061348](https://github.com/edisontw/PePe-core/actions/runs/42864061348) artifact ID `13786644093`; ARM64 [42864061217](https://github.com/edisontw/PePe-core/actions/runs/42864061217) artifact ID `13786619822`. Build+Ubuntu 22.04/24.04 PASS on each. These are GitHub Actions ZIP wrappers, not final public `.tgz` assets.
- Original PR #6 Recovery source equals the integrated source except five logging-only `(int)` casts; `wallet.cpp` matched original PR #9 by blob SHA. #12–#14 are now closed as superseded (never merged).
- Owner confirmations 2026-11-11: UTXO interrupted/resumed/restarted test already done; four ARM64 nodes enabled count 45 vs 47 at peers after another day. Do not claim this is a same-tip/same-second comparison or re-request the completed UTXO test.

## Remaining edge-case tests (not rerunning Owner's passed scenarios)

### A. Wallet persistence vs mempool admission — P1 focused failure injection

File `src/wallet/wallet.cpp`: `CWallet::CommitTransaction` now calls `wtxNew.AcceptToMemoryPool(false)` before `reservekey.KeepKey()`, `AddToWallet()` and notifications. `AddToWallet()` can return false on `WriteToDisk()` failure, but that return is ignored, an existing weakness highlighted by new ordering.

**Test:** On disposable `-regtest` wallet, make/mature UTXOs. Inject a test-only deterministic failure into wallet disk persistence after mempool acceptance (do not rely on chmod, since Berkeley DB has open handles/caches). Record txid/mempool/wallet records, key reservation and notification; restart daemon; verify rescan/history/UTXO and no blind rebroadcast or double-spend. Separately induce mempool policy rejection and confirm no phantom spend. An unconditional return false after successful mempool admission is **not** an atomic rollback. Do not patch production commit logic without review.

### B. Qt worker lifetime and full shutdown — P1 focused fault scenario

File `src/qt/coincontroldialog.cpp`: `ConsolidationBatchWork` dispatched via `QThreadPool::globalInstance()`; captures raw `CWallet*`, receiver `QPointer<CoinControlDialog>`. `done()` blocks normal dialog closing while running, but Qt application-wide shutdown/wallet teardown is separate.

**Test:** disposable wallet with many UTXOs; trigger consolidation and quit the **entire app** while signing/committing, while queued completion is pending, and while waiting for confirmation. Check no hang/use-after-free/crash and balances/UTXOs after restart. Prefer ASan on compatible toolchain. Owner's ordinary interruption/restart test is already PASS; these special timing cases are additional, not a reclassification of prior result.

### C. Recovery orphan reply/request map invariants — P2

File `src/masternodeman.cpp`: `mMnbRecoveryRequests[itMnbReplies->first]` uses `operator[]` in reply finalization; if a good-reply key had no corresponding request it could create a default request entry. This behavior predates PR #6 and may be unreachable given current invariants. Review expiry/retry/reorg paths; add a small deterministic harness using an orphan reply fixture, and check map size unchanged after processing. Never change 6-of-10 quorum, 24-block ping freshness, request wait/retry or signature checks to obtain higher ENABLED.

For field non-regression, compare exact timestamps, chain height/tip hash, individual outpoint statuses and last-ping times on two nodes. 45/47 alone does not diagnose a regression.

## Release gates still pending

1. Exact integrated Windows x86_64 Qt, daemon, CLI, tx build; test a backed-up pool-wallet copy, balance parity, Coin Control, Send All and regular payment.
2. Maintainer sign-off on Recovery (#6) and wallet persistence/worker lifetime (#9); only focused tests above where needed.
3. Normal upstream PR from approved source, final source freeze and version/release flag.
4. Fresh final Windows/Linux builds, package listing, real outer-archive SHA256, and release solely under official MattF42 repo.

## Fork cleanup

A one-time branch retirement manifest listing exact heads and decisions is in [`doc/internal/rc-pruned-branch-manifest-20261111.md`](internal/rc-pruned-branch-manifest-20261111.md). Retire obsolete test branches and unmerged experiments that are not open PR heads. Retain `master`, all nine open PR heads, `artifacts/multiplatform-b064eef` (shared build reference), and `artifacts/integrated-win64-3bf4ab3` (Windows candidate reference). Deletion is a separate guarded operation, not a merge and not evidence that tests passed.

**Human-facing summary:** [release checklist](pepepow-v2.9.0.6-rc1-release-checklist.md).