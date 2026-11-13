# PEPEPOW Core v2.9.0.6 — Draft Release Notes

> **Optional update — not yet released.** These notes describe the integrated source and verified candidate builds. Official release binaries, a final release commit and SHA256 manifests are pending.

## Changes

- **Qt wallet:** Improved handling of large transaction histories during synchronization (previously integrated in upstream PR #38). Windows read-only block-index mmap remains disabled by default (PR #39).
- **Masternode interface:** Clearer statuses, manual table refresh, copy actions and read-only collateral tier information.
- **Masternode robustness:** Defensive ping handling and Recovery peer/reply validation. Existing quorum, block freshness and network protocol rules remain unchanged.
- **Wallet usability:** Send All, Coin Control improvements and bounded UTXO consolidation, with stale-output protections.
- **Transaction persistence reporting:** Report a wallet DB write failure and the affected txid rather than incorrectly indicating success after mempool acceptance. This is a preliminary reporting mitigation, **not** atomic disk/mempool persistence.
- **Qt shutdown:** Drain consolidation workers before wallet/application teardown.
- **Linux packages:** x86_64 and ARM64 candidate archives include `PEPEPOW_qt`, `PEPEPOWd`, `PEPEPOW-cli` and `PEPEPOW-tx`.

## Candidate build verification

Official upstream master source for these tests: `1522845bcd6c75ab5086f96d2a9977eecef74849`.

| Target | GitHub Actions | Result |
| --- | --- | --- |
| Windows x86_64 | [#43279092716](https://github.com/MattF42/PePe-core/actions/runs/43279092716) | Cross-build, PE architecture/import checks and package SHA256 passed |
| Linux x86_64 | [#43278927487](https://github.com/MattF42/PePe-core/actions/runs/43278927487) | Build and Ubuntu 22.04/24.04 compatibility passed |
| Linux ARM64 | [#43279015136](https://github.com/MattF42/PePe-core/actions/runs/43279015136) | Native ARM64 build and Ubuntu 22.04/24.04 compatibility passed |

Each workflow uploaded a **test candidate** archive and a checksum manifest. Separately, an earlier RC2 version underwent successful Windows, Linux x86_64 and ARM64 field testing. The official-master Windows artifact has **not** been independently demonstrated in a physical Windows runtime test. Earlier isolated testing passed four Qt worker-drain shutdown cases and 22 Recovery orphan-reply checks.

## Upgrade notes and limitations

- Stop the wallet cleanly and back up `wallet.dat` before updating.
- When reusing old Masternode state caches, Qt/RPC may show stale ENABLED statuses. In a Windows test, refreshing `mncache.dat` and `netfulfilled.dat` after shutdown corrected the displayed status count. Back up and move these two caches only if needed; do not delete keys, wallet, blocks or chainstate.
- Switching to an older `wallet.dat` may cause a one-time rescan. Reopening the same wallet after a successful scan should not require a repeat.
- Wallet-database write failure after mempool acceptance can leave a transaction with ambiguous propagation and durable-wallet state. Inspect its txid and transaction state; do not blindly resend.
- Physical ARM64 graphical desktop behavior, unusual shutdown paths and injected production-like storage failures are not exhaustively verified.

## Publication

This version is intended as an **optional** update, without an intended consensus/protocol change; review the final source diff before distribution. The tested master contains `_CLIENT_VERSION_IS_RELEASE=false`. Before publication, commit the approved release flag, rebuild all three packages from that exact final official source SHA, verify runtime/architecture/checksums, and publish the release notes and tag with the final artifacts. Do not rename existing `-test-` archives as official `-release-` binaries.
