# One-time retired branch manifest — 2026-11-11

Internal maintenance record for `edisontw/PePe-core`, **not** an upstream release artifact.

Initial observed heads: 55 branches. Intended survivors: `master`, nine open PR heads (#4–#11 and #15) and the two still-useful test-download branches `artifacts/multiplatform-b064eef` (shared externally) and `artifacts/integrated-win64-3bf4ab3` (Windows RC comparison). These 12 must never be deleted by cleanup.

Other branches were classified as old intermediate builds, already-merged historical work, superseded closed-PR branches, or abandoned non-release experiments. Some diverged experiments have unique commits: removal is an explicit housekeeping decision, **not** a statement that their code was merged.

**Destructive cleanup guard:** before deleting each branch, verify its live HEAD equals the SHA below; reject if protected, used as an open PR head, or changed. Never force-update refs. Original source SHA provenance is retained here for traceability; any branch-linked old download paths will stop working.

| Branch | Previous HEAD SHA |
|---|---|
| `Reboot` | `089486f9173309b34e97b8b6feb956e7ba93e886` |
| `artifacts/arm64-pr6-31a35a7` | `626d8dedc2bee77481c2bc5ce43aa96e69486507` |
| `artifacts/arm64-pr6-899a44b` | `e1da98f3bf104a88068e8f0ebfd0422d8c15e69f` |
| `artifacts/arm64-pr6-afa7c83` | `f41481b8470c970295dff5567b8e3d5c8cb08597` |
| `artifacts/arm64-pr6-b40d23ed` | `985cdc0803d2d739d50216e24344f4193fb1fc6f` |
| `artifacts/arm64-pr6-fdd6923` | `6848c3339ff27ea1a71a9882c845d4285d5403b6` |
| `artifacts/linux-arm64-desktop-ddc6478` | `771ab5c95e6d6a21b328c993bba3667a6b73044b` |
| `artifacts/linux-x64-portable-6271d2f` | `d8cc8f7d3401fd20b2b35558bbb4f1ff6adc9fc0` |
| `artifacts/linux-x64-pr14-5971b3f` | `cb997ff8fcdf9f50db4f2bc35a191c58b64584b6` |
| `artifacts/qt-pr3-f4b4ea30` | `c7d75261a7ca52e55095ed65e895da4cf48b445d` |
| `artifacts/rc1-d29b6cc-linux-x64` | `af1b75f43976a3d8062076cba699ab00e759365e` |
| `artifacts/win64-leveldb-io-423a6dc` | `41505b767632ff567c0addbc396699d0a42a6d43` |
| `artifacts/win64-leveldb-io-profile-5063b52` | `86c139d7b03d28c62771576573be141ccda20fdf` |
| `artifacts/win64-mmap-3f83d4b` | `3f1ecee75b061bcf73d8bc044990ed65c2ffe567` |
| `artifacts/win64-mmap-8d6a1af` | `ed006564c1691fe5557a23d59c01ef1eb272d4f4` |
| `artifacts/win64-mmap-compaction-e6c5b82` | `dbc8c560e2cd7594edb232a6917a26affaf7c5b5` |
| `artifacts/win64-mmap-smoke-85bf11e` | `238320582445f6192b6a7591b2051e7fce11528c` |
| `artifacts/win64-pr4-8-4f56f14` | `352b26a4253f6d63ca3922c2c96759fc9d2607bb` |
| `artifacts/win64-pr4-10-240b3d4` | `82094639116de8071510da43320991071b196a6e` |
| `artifacts/win64-pr4-10-f9b1faf` | `af9a45189218a1c925f9d87275b98244410a21b9` |
| `artifacts/win64-pr9-refresh-b064eef` | `36a96bc2ee027264f6df7c6f77bce545055c9d8d` |
| `artifacts/win64-startup-perf-1b6646d` | `c579e5dc27beba07c7598bc3885125973426b2cb` |
| `build/linux-arm64-desktop-qt` | `ddc6478db4d391e80954ae4d2fddebc133472201` |
| `build/linux-x64-appimage-ci` | `6271d2f4e8d83d919da7d8f452dff943df30cea1` |
| `docs/pr38-pr39-win64-acceptance` | `d3851cfee9ed6411930fc67f9a767444186c8dd3` |
| `edisontw-fix-splash-overlap` | `f0cb470b22fd64fea05ddc46864b35fe28a53cef` |
| `fix/qt-coincontrol-contrast-default-tabs` | `5971b3fa6e1a7296f02b6e6a0170532376a88d5f` |
| `perf/qt-large-wallet` | `3d583f7a493b4ec858d8d9b2ce6a04329c19f5fc` |
| `perf/startup-block-index` | `1b6646d7cdbb140c13327f858ccba5446e29da65` |
| `perf/startup-leveldb` | `37037b468d72b5e87f8792a9ea475af240e814fe` |
| `perf/startup-leveldb-io` | `423a6dc152a1f94718a94a43a5fcbbb46092b26b` |
| `perf/startup-leveldb-io-profile` | `f5c8abc0b6934b1c4a192adbff8c71257283e634` |
| `perf/startup-win-mmap` | `8098047b2c753c94fa0cb0e62e84bf35ee389a8c` |
| `perf/startup-win-mmap-review` | `fe30eda859439c88780576e1c16c2cfb262c94ae` |
| `private-send-recalibration` | `1f5bc9c66fb3af414161d0d5dbb6976e2d6ce436` |
| `realsetvin-patch-1` | `0b55ad27439d964341944ef3f5b0501ae692b423` |
| `realsetvin-patch-2` | `b77f88f7e7f13a8ad5822ae21a96a162ccc70a0c` |
| `realsetvin-patch-3` | `3c0db7ce06051561c27ea931831d4700148140fb` |
| `realsetvin-patch-4-1` | `88cae282cae487615aa8413303e7980074f75dd4` |
| `realsetvin-patch-4` | `41db31954fe6d5755404ba1b7bc1c5d15e9cb5bb` |
| `realsetvin-patch-5` | `3c4da64c11e01408990b3925258cfe12699ae4b8` |
| `realsetvin-patch-6` | `1aa2785e52098b14bd656bb74759e67b3d741897` |
| `realsetvin-patch-7` | `5388bf1d9bc6999036ce6afaa04d3566aa606380` |

Release candidate remains Draft. Do not touch official `MattF42/PePe-core`, either master, tags or published Releases.