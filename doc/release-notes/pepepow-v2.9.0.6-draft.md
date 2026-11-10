# PEPEPOW Core v2.9.0.6 — DRAFT Release Notes

> **Draft only; not yet an official release.** Features below are **candidates**, not a guarantee of final inclusion. This file must be reconciled with the final merged release commit and acceptance results before publication.

## Summary

Proposed **optional** maintenance release following [v2.9.0.5](https://github.com/MattF42/PePe-core/releases/tag/v2.9.0.5), focused on Windows Qt performance, usability, wallet handling and defensive masternode Recovery fixes. It is intended **not** to require a chain fork, change consensus parameters, reduce Recovery quorum, or relax signature/ping verification. Final classification as OPTIONAL depends on the audited final diff.

## Improvements already merged since v2.9.0.5

- **Qt large-wallet responsiveness** (upstream [#38](https://github.com/MattF42/PePe-core/pull/38)): avoid heavy transaction-history GUI refresh work during chain catch-up. The Windows Qt pool-wallet freeze was reported fixed in manual testing.
- **Windows block-index I/O** (upstream [#39](https://github.com/MattF42/PePe-core/pull/39)): an **opt-in** read-only mmap path for block-index LevelDB tables, disabled by default, with ordinary read fallback. It does not alter consensus or block-index data format.

## Proposed additional fixes and features — pending acceptance

- Masternode UI: fix sortable table updates, improve refresh and provide IP/payee copy actions ([fork #4](https://github.com/edisontw/PePe-core/pull/4)).
- Masternode validation: reject a ping referencing an unknown block index entry instead of dereferencing a missing iterator ([fork #5](https://github.com/edisontw/PePe-core/pull/5)).
- Masternode Recovery: prefer distinct locally ENABLED peers, defer infeasible requests, validate recent signed replies before reprocessing. The **existing 6-of-10 quorum, 24-block freshness limit, 60-second response wait, three-hour retry cooldown and final verification remain in place** ([fork #6](https://github.com/edisontw/PePe-core/pull/6)). Live ARM64 testing remains under review.
- Masternode status: read-only T1–T4 collateral tier reporting in RPC and Qt; no change to collateral thresholds or payment allocation ([fork #7](https://github.com/edisontw/PePe-core/pull/7)).
- Qt Send All: fill a normal payment using spendable inputs and subtract fees from the amount ([fork #8](https://github.com/edisontw/PePe-core/pull/8)).
- Qt/wallet UTXO consolidation: one-click, wallet-owned destination, exact input selection, max 500 inputs per batch and signed transaction size below 80 KB. Fix stale selections and locally phantom-spent coins after rejected sends ([fork #9](https://github.com/edisontw/PePe-core/pull/9)). **Wallet core commit ordering is changed** and requires focused maintainer review and real-wallet tests.
- Qt splash screen: improve contrast, loading-progress placement, and overlapping copyright lines ([fork #10](https://github.com/edisontw/PePe-core/pull/10)).

## Proposed Qt presentation and Linux packaging additions — still Draft

- **Qt Coin Control UI:** clearer checked/unchecked/partial selection indicators; tree-group amount receives a Σ subtotal marker with distinct grouping/source versus actual UTXO address tooltips. The 100,000,000-PEPEW example shows one real UTXO under an aggregate address group, not two collateral outputs. On fresh installations Coin Control and the Masternodes tab are enabled by default; existing explicit settings stay unchanged ([fork #14](https://github.com/edisontw/PePe-core/pull/14)).
- **Linux x86_64:** package Qt + independently copyable daemon/CLI/tx together as one archive, as in v2.9.0.5. Qt retains the **`PEPEPOW_qt`** executable name; the portable implementation internally uses an AppImage runtime, bundling Qt/Boost libraries. The headless binaries use statically linked third-party dependencies and ordinary Linux system libraries ([fork #12](https://github.com/edisontw/PePe-core/pull/12)). FUSE or an extraction fallback may still be needed for Qt.
- **Linux ARM64:** package Qt + daemon/CLI/tx together as one archive; Qt is a native AArch64 ELF with bundled shared Qt libraries/plugins, while headless binaries remain independently usable ([fork #13](https://github.com/edisontw/PePe-core/pull/13)).
- **Testing limitation accepted by the owner:** Linux ARM64 Desktop was built and exercised on native ARM64 CI in Ubuntu 22.04/24.04 Xvfb, but *physical desktop interaction was not tested and is expressly not a release blocker*. Do not describe this as passed real-desktop testing. Four ARM64 masternode nodes were reported healthy after about a day, separately from the ARM64 GUI test.

Integration of #12/#13/#14 with RC1 is staged on `release/v2.9.0.6-rc1-platform-staging`; final combined CI/packaging evidence must be recorded before publication. Do not reuse the individual PR artifact SHA256 values for final release packages.

## Upgrade notes (to verify before publication)

- Back up `wallet.dat` and shut down PEPEPOW Core cleanly before replacing binaries.
- Do not test new UTXO consolidation with an irreplaceable wallet. Use backup wallets/test funds until acceptance is complete.
- No new mandatory network protocol or consensus requirement is *intended*, but this statement must be confirmed against the exact final release commit.
- Windows mmap remains **disabled unless explicitly opted in**.
- The above text is not an authorization to upgrade production nodes or claim all listed wallet functions are validated.

## Downloads and verification — PENDING

No official v2.9.0.6 binaries, hashes or signed release tag have been produced. The [multiplatform integration-test builds](https://github.com/edisontw/PePe-core/tree/artifacts/multiplatform-b064eef/downloads/multiplatform-afe0c2e) were generated from an earlier untagged test commit, not from the release candidate or a final upstream release commit; **do not publish those test archives as official release assets**.

Final publication requires an exact upstream release commit, fresh Windows x86_64/Linux x86_64/Linux ARM64 builds from that commit, actual smoke/field validation, file hashes and an official GitHub Release.

## Outstanding release blockers

1. Maintainer review and native ARM64 acceptance of Recovery (#6), without weakening the quorum or ping checks.
2. Real-wallet testing and review of transaction persistence/notification/concurrency for #9.
3. Complete Qt combined-feature test including #4/#7 and #8/#9 overlaps.
4. Final source freeze, version-as-release switch, reproducible build provenance, binaries and checksum verification.

See [RC1 release gates](../pepepow-v2.9.0.6-rc1-release-checklist.md).
