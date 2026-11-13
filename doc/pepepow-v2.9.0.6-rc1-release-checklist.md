# PEPEPOW Core v2.9.0.6 — Release Verification Checklist

This checklist applies to the **optional update** after upstream integration, not to the original RC1 branch. Source SHA and build results must be checked again before publication.

## Integrated source and verification

- [x] Integrated via [upstream PR #41](https://github.com/MattF42/PePe-core/pull/41), official master SHA `1522845bcd6c75ab5086f96d2a9977eecef74849` at this audit.
- [x] Linux x86_64 build and Ubuntu 22.04/24.04 compatibility — [Actions #43278927487](https://github.com/MattF42/PePe-core/actions/runs/43278927487).
- [x] Native ARM64 build and Ubuntu 22.04/24.04 compatibility — [Actions #43279015136](https://github.com/MattF42/PePe-core/actions/runs/43279015136).
- [x] Windows x86_64 cross-build, PE/DLL checks and candidate archive — [Actions #43279092716](https://github.com/MattF42/PePe-core/actions/runs/43279092716).
- [x] Candidate archives were checked against their generated SHA256 manifests.
- [x] Earlier RC2 field tests exercised Windows, Linux x86_64 and ARM64.
- [x] Qt worker-drain fix passed four controlled test windows; orphan Recovery guard passed 22 assertions.

## Feature scope and limitations

- [x] Wallet DB failure path reports txid and avoids false success; mempool and database durability remain non-atomic.
- [x] Dedicated Qt UTXO consolidation worker pool is drained on shutdown.
- [x] Orphan Recovery replies do not insert a missing request entry.
- [x] Qt user interface, Send All, bounded UTXO consolidation, Masternode table/status and read-only collateral tiers are integrated.
- [ ] Complete final check for unintended consensus, protocol, wallet-format, quorum or spork changes.
- [ ] Assess whether final official Windows archive requires an additional physical Windows runtime check.
- [ ] Note limited ARM64 graphics and exceptional database/shutdown fault coverage.

## Publication gates — not yet completed

- [ ] Finalize release notes and document upgrade precautions.
- [ ] Commit `_CLIENT_VERSION_IS_RELEASE=true` only after the optional-version source check.
- [ ] Rebuild Windows x86_64, Linux x86_64 and native ARM64 from **the final release commit**.
- [ ] Verify candidate vs release version strings, executable formats, archive contents, dependencies and SHA256.
- [ ] Ensure no `wallet.dat`, private keys, seeds or debug logs are included in packages.
- [ ] Create the official `v2.9.0.6` tag and GitHub Release only with matching final-source artifacts.
- [ ] Keep automated GitHub Actions builds separate from publication; no auto-Release on ordinary pushes.

## Reference

[Draft release notes](release-notes/pepepow-v2.9.0.6-draft.md) and [release source provenance](v2.9.0.6-upstream-review-handoff.md).
