# Windows x86_64 Qt post-merge integration validation (PR #38 + #39)

Validation date: **2026-10-14**. Status: **Windows functional smoke test PASS**.
This is a post-merge testing record for maintainers, **not** an official
PEPEPOW Core release or a controlled performance benchmark.

## Source and test build

- Canonical upstream: `MattF42/PePe-core:master`, merge commit
  [`3bf4ab301cc5bbddc854dd4dd07010bdf3de3e13`](https://github.com/MattF42/PePe-core/commit/3bf4ab301cc5bbddc854dd4dd07010bdf3de3e13).
- Qt large-history wallet GUI fix: [PR #38](https://github.com/MattF42/PePe-core/pull/38),
  merge commit `2d3ff9093a3842c52e220b2bd9232b7f2c49930f`.
- Optional Windows block-index read-only mmap: [PR #39](https://github.com/MattF42/PePe-core/pull/39),
  merge commit `3bf4ab301cc5bbddc854dd4dd07010bdf3de3e13`.
- Built as a Windows x86_64 PE32+ GUI executable with static Qt 5.5.0 on
  Ubuntu 24.04.5 using MinGW-w64 GCC 13.2.0. The builder recorded a clean
  Git archive of the exact upstream commit; no source edits were made.
  The legacy toolchain required environment-only compatibility workarounds.
  UPnP was disabled in the available build dependency prefix.
- Build and static PE-format checks: **PASS**. The build report's
  "Windows runtime NOT TESTED" statement refers to its state immediately
  after compilation; the separately completed Windows tests are below.

### Test artifact and checksums

The pre-release test artifact is intentionally **not stored in the upstream
source tree**:

- [Windows Qt integrated test ZIP (fixed artifact commit)](https://raw.githubusercontent.com/edisontw/PePe-core/4199da2f612b80feb94032c6bcef6158e1e312b9/PEPEPOW-Qt-win64-integrated-3bf4ab3.zip)
  (`PEPEPOW-Qt-win64-integrated-3bf4ab3.zip`, 29,403,390 bytes).
- ZIP SHA256:
  `11b0a0481fdcd7acddc4b5ef66aa3cb91f9f32e088bae966ecf7889d88ace766`.
- Contained `PEPEPOW_qt.exe`: 46,510,667 bytes; SHA256:
  `ea5709dd02b38de68db0615209ef21369687ebb65b444ab72daa4a832ee34d65`.
- Recorded source archive SHA256:
  `d8092936907b030718b067a8467a93b9cc37346f0a5f31eafb268712256dcf9f`.

On a separate Windows machine the tester ran the package PowerShell verifier.
Its output confirmed the downloaded ZIP SHA256, extracted EXE checksum against
`SHA256SUMS.txt`, and required source commit in both `BUILD-REPORT.md` and
`SOURCE-PROVENANCE.txt`: **all PASS**. This confirms package consistency
with the builder's recorded provenance, **not** independent reproducible
compilation or cryptographic attestation of the original runtime binary.

## Windows runtime test

The tester supplied `debug_pr3839.log` from two runs of the integrated Windows
Qt binary against a real, large-history mining-pool wallet (about 25,000
wallet transaction records; over 5.1 million block-index entries). Private
wallet and network details from the raw log are intentionally excluded.

| Checkpoint | Default: mmap off | Explicit opt-in: `-winmmapblockindex=1` |
| --- | ---: | ---: |
| Process started | 14:39:23 | 14:47:58 |
| Block-index load | 221,971 ms | 132,092 ms |
| Wallet load | 27,002 ms | 461 ms |
| `Done loading` | 14:43:37 | 14:50:11 |
| Mmap counters | No enabled/summary message | 543 attempts; 543 mapped; 0 fallback |
| Recent-block database consistency verification | PASS | PASS |
| Network catch-up / additional block processing | PASS | PASS |
| Normal `Shutdown: done` | 14:46:29 | 14:52:54 |

- Both runs loaded the real wallet, passed recent-block database consistency
  checks, processed newly received blocks, and shut down normally.
- The opt-in run exercised the Windows block-index mmap implementation
  successfully with no mapping fallback; the default run did not enable it.
- The tester independently confirmed the Qt GUI remained responsive when
  using the large-history pool wallet: the previous freezing problem was
  **not reproduced (manual GUI PASS)**.
- No fatal startup errors, detected LevelDB corruption, or mmap mapping
  failures appeared in the supplied log.
- Nonfatal `SUPERBLOCK_EXPECTED` diagnostic messages occurred during sync.
  Their cause was not established by these tests.

## Interpretation and release considerations

1. **Mmap is disabled by default** in the merged source:
   `GetBoolArg("-winmmapblockindex", false)`. It is enabled only with
   `-winmmapblockindex=1`, and mapping failures retain a ReadFile fallback.
   No consensus or persistent database-format change is intended.
2. **No causal speedup claim.** The on/off runs were sequential, not controlled
   for Windows filesystem cache, chain catch-up, wallet state or background
   activity. The lower observed load time in the second run must not be
   presented as measured mmap acceleration.
3. The test does not exhaustively establish mapped-view lifecycle safety,
   unusual Windows file-deletion races, long-duration behavior or
   reproducible builds. Maintain the opt-in, default-off behavior.
4. This is a **tested Windows release candidate artifact**, not an official
   release. Upstream maintainers remain responsible for any release tag,
   packaging, versioning and distribution decisions.
5. The raw debug log remains with the tester; it should not be committed
   publicly because it contains local paths, wallet and network details.

These findings document post-merge validation without introducing any new
application code or binary artifacts into the upstream source repository.
