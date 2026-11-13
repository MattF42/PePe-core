# PEPEPOW Core v2.9.0.6 — Technical Risk and Validation Record

This file records source-level failure modes and test coverage for the optional update. Earlier experimental findings are retained for traceability; their original statuses are not current release gates.

## Integrated source

- Official integration: [PR #41](https://github.com/MattF42/PePe-core/pull/41), master `1522845bcd6c75ab5086f96d2a9977eecef74849`.
- Linux x86_64 [CI](https://github.com/MattF42/PePe-core/actions/runs/43278927487), native ARM64 [CI](https://github.com/MattF42/PePe-core/actions/runs/43279015136) and Windows x86_64 [CI](https://github.com/MattF42/PePe-core/actions/runs/43279092716) completed successfully from that source.
- Fork RC candidates are historical source and test evidence, not final release artifacts.

## A. Wallet persistence vs mempool admission

**Risk:** A transaction can enter the mempool before wallet database persistence finishes. If a Berkeley DB write then fails, the wallet may not retain a durable record after restart even though a transaction id exists and network propagation is possible.

**Included mitigation:** `CommitTransaction` detects `AddToWallet` failure, returns an error including txid to Qt/RPC and avoids the explicit relay call. This is a reporting improvement, not a rollback/atomicity guarantee.

**Additional testing:** use a disposable regtest wallet to inject failures after mempool admission; inspect txid, mempool, wallet records and state after restart. Avoid deliberately damaging production `wallet.dat`.

## B. Qt consolidation worker lifetime

**Risk:** Queued or active consolidation work could outlive the Qt dialog/wallet during shutdown.

**Included mitigation:** dedicated worker pool, stop queuing and drain before teardown. A controlled shutdown test passed four timing scenarios after the change.

**Additional testing:** disposable-wallet shutdown while signing, committing and awaiting confirmation, checking for hang/crash/duplicate transaction. Production-like interruption combinations are not exhausted.

## C. Masternode Recovery orphan replies

**Risk:** A missing request accessed through an indexed map lookup could create an unintended default request entry.

**Included mitigation:** guarded request lookup; a deterministic fixture passed 22/22 assertions. Existing six-of-ten quorum, signature checks, ping freshness and retry timing are unchanged.

**Additional testing:** exercise actual expiry/retry state transitions. When comparing node status, use matched tip heights and outpoints; aggregate enabled-node counts alone do not prove recovery causation.

## D. Candidate build and packaging

Three official-master candidate workflows compiled and uploaded test archives; Linux compatibility passed on Ubuntu 22.04/24.04, including native ARM64. These artifacts use the candidate release flag and must not be renamed as final published binaries.

See the [release verification checklist](pepepow-v2.9.0.6-rc1-release-checklist.md).

## Historical maintenance

A one-time fork branch cleanup is recorded in [the retired branch manifest](internal/rc-pruned-branch-manifest-20261111.md). The manifest is historical repository-maintenance provenance, not source or runtime acceptance.
