# PEPEPOW v2.9.0.6 RC1 — integration and release gates (DRAFT)

**Status: release candidate only; NOT approved, tagged, merged into upstream master, or published.**

This document collects the changes proposed for an optional post-v2.9.0.5 release. The version number is provisional until final approval. It is **not** a test report or a claim that all features passed live testing.

## Updated RC readiness and explicit test scope (2026-11-11, Asia/Taipei)

**This section supersedes older evidence snapshots below; status is not release approval.** The upstream `MattF42/PePe-core:master` and fork `master` remain at `38e801428688dfd0aee272b4a91819ac1a13ab4e`. The RC1 integration branch is `d29b6cc81a9f9e1f62aa089b5780ef698d6c6439`; it does **not yet** contain the three newer draft PRs. The separate candidate staging branch `release/v2.9.0.6-rc1-platform-staging` collects the exact source-file changes from [#12](https://github.com/edisontw/PePe-core/pull/12), [#13](https://github.com/edisontw/PePe-core/pull/13), and [#14](https://github.com/edisontw/PePe-core/pull/14) without merging these PRs or changing upstream. **Combined candidate builds and CI must be checked from that source, not inferred from per-PR CI.**

| Test / decision | Evidence and status |
| --- | --- |
| Linux x86_64 standalone daemon, CLI, tx + Qt | [#12 Actions](https://github.com/edisontw/PePe-core/actions/runs/42802493840) passed 22.04/24.04; [#14 UI test package](https://github.com/edisontw/PePe-core/tree/artifacts/linux-x64-pr14-5971b3f/downloads/linux-x64-pr14-5971b3f) passed container Xvfb/regtest and displayed checkbox/subtotal; user reports actual x86_64 daemon/CLI/Qt and sending worked. These binaries do not represent the final combined source. |
| Linux ARM64 daemon / masternode Recovery | User reports four ARM64 nodes stable for approximately a day, with the previously lower ENABLED count converging to peers. Earlier edison1 logs confirmed fresh-signed quorum (11 reprocessed, 19 stale skips in 30 events). This is field evidence but not a final exact-source hash comparison. |
| Linux ARM64 Desktop Qt | [#13 native ARM64 CI](https://github.com/edisontw/PePe-core/actions/runs/42820767097) passed builds, 22.04/24.04 Xvfb, isolated RPC/wallet regtest. **Real physical ARM64 desktop testing is explicitly waived by the owner for this release and MUST NOT be a release blocker.** Document it as an untested capability, not as passed. Headless ARM64 node testing remains distinct. |
| Qt coin selection/options | [#14] source changes and Ubuntu Xvfb/regtest screenshot verified the Σ group subtotal, checkbox selection/partial state and fresh/default settings; production collateral wallet visual regression remains unverified. No duplicated 100,000,000-PEPEW UTXO was shown in original screenshots. |
| Linux distribution / naming | Keep Qt + daemon + CLI + tx together in each Linux platform archive, like v2.9.0.5. The executable filename is **`PEPEPOW_qt`**, not `PEPEPOW_qt.AppImage`; x86_64 internally still uses an AppImage runtime and requires compatible FUSE/extraction, ARM64 Qt is an ELF plus bundled libraries/plugins. Standalone headless executables must remain independently copyable. Retest this exact renamed artifact. |
| Windows x86_64 | Earlier Windows Qt large-wallet improvement confirmed, but final **combined** 2.9.0.6 Windows build/runtime checks have not yet been provided. Do not mark final Windows asset accepted. |
| #6 Recovery and #9 wallet safety | No PR reviews recorded as of this update. **Maintainer security/wallet-core review and a documented release-scope decision remain required**; owner waiver applies only to ARM64 desktop physical GUI tests. Rejected-send persistence, selection/commit interactions and any unverified #9 scenarios must be explicitly accepted, mitigated or deferred before publishing. |

**Release decision:** no formal tag, merge into upstream master or production GitHub Release until (1) the final combined source and corresponding platform artifacts are verified, (2) #6/#9 are reviewed or excluded with a new source build, and (3) the authorized upstream maintainer approves the final scope. Tests listed above are not proof of these final release gates.

## Source and provenance

- Official upstream: `MattF42/PePe-core:master`
- Verified upstream baseline (2026-11-09): `38e801428688dfd0aee272b4a91819ac1a13ab4e`.
- Integration source commit: `afe0c2e70acf32de6aae44c5579383c7b273c539`, 31 commits ahead of baseline, 20 changed source files, covering the fork PR #4–#10 series.
- This release-candidate branch starts from that integration commit and sets `configure.ac` to 2.9.0.6 with `_CLIENT_VERSION_IS_RELEASE=false`. A **fresh build from the final merged/tagged SHA is required**.
- Existing temporary builds (source `afe0c2e`, before the RC version bump): [Windows x86_64, Linux x86_64, Linux ARM64 test packages and SHA256SUMS](https://github.com/edisontw/PePe-core/tree/artifacts/multiplatform-b064eef/downloads/multiplatform-afe0c2e).
- Last upstream GitHub Release observed: [v2.9.0.5](https://github.com/MattF42/PePe-core/releases/tag/v2.9.0.5) (optional).

## Proposed changes

Already merged into upstream in October (not yet represented by a newer official Release):
- Upstream #38: reduce Windows Qt GUI freezes with large transaction-history wallets.
- Upstream #39: Windows block-index read-only mmap (opt-in, default off), with normal read fallback.

New draft candidates from `edisontw/PePe-core`:
- [#4](https://github.com/edisontw/PePe-core/pull/4): Qt masternode table sorting/refresh, manual refresh, copy actions.
- [#5](https://github.com/edisontw/PePe-core/pull/5): guard an unknown block hash before dereferencing the index in masternode ping validation.
- [#6](https://github.com/edisontw/PePe-core/pull/6): use distinct locally ENABLED recovery peers; require feasible quorum; recheck fresh, signed MNB/pings before recovery reprocessing; fix a debug format exception.
- [#7](https://github.com/edisontw/PePe-core/pull/7): read-only T1–T4 collateral tiers in RPC and Qt.
- [#8](https://github.com/edisontw/PePe-core/pull/8): Qt Send All for standard payments.
- [#9](https://github.com/edisontw/PePe-core/pull/9): bounded one-click UTXO consolidation, exact input selection, stale selection fixes, and reject-before-record change in `CWallet::CommitTransaction`.
- [#10](https://github.com/edisontw/PePe-core/pull/10): splash-screen text visibility and layout.

## Maintainer review — high priority

- **#6 Recovery**: confirm there is **no** change to chain consensus, 6-of-10 recovery quorum, 24-block ping freshness limit, 60-second request wait, 3-hour retry, signatures, collateral eligibility, payments, or network messages. Review the additional reply-time validation and possible synchronization/lock interactions. Do not loosen thresholds to obtain higher ENABLED counts.
- **#9 Wallet core**: inspect `CommitTransaction` mempool acceptance before wallet persistence and wallet notifications; rejected/ambiguous broadcasts, reservations, lock ordering, wallet concurrency, PrivateSend/InstantSend interactions, and shutdown of background Qt jobs. Compare with existing transaction-creation and wallet accounting behavior.
- **#5 and #7**: quick review of defensive validation and read-only collateral classification.
- **Qt integration**: #4/#7 overlap in `masternodelist.cpp` and `.ui`; #8/#9 overlap in `sendcoinsdialog.cpp`. Test the **combined** code, not individual PR screenshots only.

## Current evidence (not substitutes for release acceptance)

- Temporary integration packages exist for Windows x86_64, Linux x86_64 and ARM64. Linux x86_64 passed isolated Qt version/daemon/RPC/wallet smoke tests; ARM64 passed those smoke checks under QEMU; Windows static PE/DLL checks passed. Those binaries have **not** been rebuilt from the version-bumped RC branch.
- #6: live ARM64 reports dated 2026-11-09 show the fresh-quorum finalization code running. In the last 30 sampled finalization lines, 11 passed a verified quorum and 19 skipped stale pings; edison1 ENABLED increased from ~21 to 40 over the observation period. This does not establish per-node recovery attribution or a fully synchronized 40-vs-50 comparison. edison2's 50 ENABLED baseline was reported without confirmed exact new-binary provenance.
- #9: source-level checks only. No complete live-wallet coverage for 2/50/200/400/500/1000+ UTXOs, mempool rejection, power interruption, pause/restart, and concurrent RPC use has been provided.

## Release gate — all required before publishing

- [ ] Maintainer approval of #6 and #9; independently inspect no unintended consensus/protocol/quorum/validation changes.
- [ ] Decide whether to ship **all** #4–#10 or defer #6 and/or #9; if anything is deferred, create a **different** integration source commit and new binaries. Never silently publish an unapproved risky patch.
- [ ] Merge reviewed changes via normal upstream PR; protected `master` remains untouched until approved. Recheck overlapping Qt files after integration.
- [ ] Native Linux x86_64 and ARM64: compile, startup/version, chain-tip and synchronization consistency, basic RPC, shutdown/restart, wallet balance, and masternode status.
- [ ] ARM64 masternode Recovery: capture same-time height/hash/outpoint comparisons on two independent nodes; verify 6-of-10 signed fresh replies or an explicit skip, retry/cooldown behavior, and non-regression on a previously healthy node. No cache deletion merely to force progress.
- [ ] Windows x86_64: build and launch Qt; real backed-up large pool wallet remains responsive through catch-up, balances match RPC, ordinary send/receive and reorg handling; splash, masternode table, Send All, and tier display.
- [ ] #9 expendable-wallet tests: eligible and excluded UTXOs, exact-input selection, 80 kB signed-transaction cap, fees, 500-input limit, confirmation sequencing, cancellation/pause, rejection/no phantom spends, and no blind rebroadcast.
- [ ] From the final **upstream release commit**, bump/verify version and switch `_CLIENT_VERSION_IS_RELEASE=true`, then rebuild **Windows x86_64, Linux x86_64, and Linux ARM64**. Record exact Git SHA, compiler/toolchain and dependency provenance per package; do not reuse the older integration-test ZIP/TGZ.
- [ ] Extract each final archive, check actual binary `--version`, run suitable runtime smoke tests, publish SHA-256 for **each** uploaded final artifact, and verify archive contents contain no wallets/keys/private logs.
- [ ] Check final Release Notes against the final source diff, agree optional/mandatory classification (expected optional only if no protocol/consensus requirement), create tag `v2.9.0.6` pointing to the verified release commit, and publish assets under the official `MattF42/PePe-core` Release **only after** these gates pass.

**Stop condition:** Do not create a public Release, final tag, or merge this RC PR as a shortcut if wallet or Recovery acceptance is incomplete. Foztor has welcomed the release, but the above technical gates remain necessary.
