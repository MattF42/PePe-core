# Experimental Windows block-index mmap (isolated review)

This document describes the **minimal mmap-only changes** proposed against
`master`. The review branch is deliberately separate from both the existing
Qt large-wallet Draft PR #2 and the older startup profiling work.

## Scope and default

- Windows x86_64 only. Windows x86 / POSIX platforms retain their old paths.
- Off by default. Opt in at startup with `-winmmapblockindex=1`.
- Eligible files are direct `blocks/index/*.ldb` and `blocks/index/*.sst`
  (immutable LevelDB table files). `chainstate`, `wallet.dat`, logs,
  manifests and writable SST files are not mapped by this option.
- `CreateFileMappingW(PAGE_READONLY)` and `MapViewOfFile(FILE_MAP_READ)`
  provide read-only mapped views. The existing `ReadFile` random-access
  reader is kept as the fallback on mapping failures.
- An Env-scoped `MmapLimiter` limits the number of outstanding views to
  1,000. TableCache/iterator reference lifetimes govern when a view unmaps.
- The database format, key/value encoding, checksum verification and
  consensus logic are unchanged. No rescan/reindex/migration is requested.

Opt-in example:

```text
PEPEPOW_qt.exe -winmmapblockindex=1
```

The option is documented in Windows `-help-debug`. With it enabled, startup
logs eligibility attempts, mapped opens and fallback counts:

```text
Experimental Windows mmap enabled for blocks/index LevelDB table reads
Windows block-index mmap summary: attempts=... mapped=... fallback=...
```

These counters represent **file opens**, not reads or bytes. Mapping does not
guarantee that a read is served from RAM; page faults and actual disk reads
are still possible.

## Windows evidence available on the experimental branch

The actual Windows Qt experiment exercised mmap against a large PEPEPOW
block-index database with approximately 5.09 million index entries:

```text
Windows block-index mmap summary: attempts=533 mapped=533 fallback=0 (limit=0 open=0 size=0 mapping=0 view=0)
```

Successful startup and normal process shutdown were reported; this confirms
mapping was exercised, **not** that mmap reliably accelerates startup.

A separate Windows x86_64 LevelDB smoke executable built from the experiment
source was executed twice with consistent results:

```text
PASS readfile live_tables=2 disk_tables=2 mmap_attempts=0 mapped=0
PASS mmap live_tables=2 disk_tables=2 mmap_attempts=212 mapped=212
PASS Windows block-index mmap compaction regression
```

The smoke writes and overwrites synthetic keys, forces compaction, verifies
reads, compares live/physical SST counts and destroys its own scratch DB.
It specifically checks for obsolete SST files that might remain if Windows
refused a delete while a view was mapped. It does not cover every concurrency
or external file-sharing situation.

### 2026-10-14 isolated PR #3 Qt runtime (user-supplied `debug_pr3.log`)

The user supplied a Windows Qt runtime log identified as the PR #3 test.
Important checkpoints, on a real PEPEPOW datadir containing `wallet3.dat`:

```text
11:03:47 Experimental Windows mmap enabled for blocks/index LevelDB table reads
11:06:53 No coin database inconsistencies in last 289 blocks (322 transactions)
11:06:53  block index          186490ms
11:06:53 Windows block-index mmap summary: attempts=541 mapped=541 fallback=0 (limit=0 open=0 size=0 mapping=0 view=0)
11:07:19  wallet                26263ms
11:07:20 init message: Done loading
11:16:35 Shutdown: done
```

The log shows `mapBlockIndex.size() = 5102660`, wallet load, continued
peer/block synchronization (tip 5102477 -> 5105971, progress 1.000000),
and a normal clean shutdown. It contains no LevelDB corruption, reindex,
or mmap failure messages. **Functional startup/sync/shutdown on Windows:
PASS for this run.**

The same log has unrelated-looking nonfatal protocol warnings:
`ERROR: Requesting unset send version for node` (11 instances) and
`ProcessMessages(version, 108 bytes) FAILED peer=12`. It also contains
35 periodic `Double SUPERBLOCK_EXPECTED` diagnostics during syncing.
Those did not prevent reaching the network tip or shutdown; their root
causes were not investigated in this mmap review.

### 2026-10-14 isolated-branch build and artifact verification

A separate `BUILD-REPORT.md` packaged with the Windows Qt build records:

- **Cross-build PASS** from a clean `git archive` of
  `f4b4ea30fe381bd2ce599aa55942e8411b3fc4a0` (the exact PR #3 source
  HEAD at build time; later branch commits are documentation-only).
- Ubuntu 24.04.5 / MinGW-w64 x86_64 GCC 13.2 / static Qt 5.5.0;
  `make -C src -j4 qt/PEPEPOW_qt.exe` completed without compile/link errors.
- PE32+ AMD64 Windows GUI binary, 46,493,259 bytes. The relevant Windows
  mmap flag and summary-log strings are present.
- The report's original “Windows runtime: NOT TESTED” refers to **build
  time**. A subsequent user-operated Windows Qt test is documented above.

The package resides on the independent
[`artifacts/qt-pr3-f4b4ea30`](https://github.com/edisontw/PePe-core/tree/artifacts/qt-pr3-f4b4ea30)
branch as `PEPEPOW-Qt-PR3-mmap-f4b4ea30.zip`.

| Item | SHA256 | Evidence |
| --- | --- | --- |
| Published ZIP | `162456114734cc06f390e4fd330c8ce873affe9ef8aca63b57d367b58937ace0` | Published `SHA256SUMS.txt`; user's Windows PowerShell reported `PASS: PR3 ZIP SHA256 verified` |
| `PEPEPOW_qt.exe` | `ed5bc158938516111e9a67ad85e3dcb2c8406e231a693e593844c81a57a96623` | Build report, packaged `SHA256SUMS.txt`, and Windows `Get-FileHash` match |
| `BUILD-REPORT.md` | `3cf7e95f17b46b89cbeed0e49817bda26252cfe180c2714c46c568ef83ef0c1d` | Packaged `SHA256SUMS.txt`; independently checked against user-uploaded report |

**Result:** the published ZIP integrity and extracted executable identity
match the builder-supplied manifest and clean-source build report.
This completes the **build/artifact provenance evidence gate** for maintainer
review. The evidence is a verified chain of builder report, published ZIP
checksum and user-computed hashes; it is not a separate reproducible-build
comparison by a second compiler.

The log itself does not embed its own executable hash, but the user
supplied that run as the PR #3 Windows validation. No need to repeat
startup, rescan, wallet, or full compaction testing solely for this
artifact verification. There was no automated GitHub Actions CI run.

**No speedup claim:** 186.49 seconds for the block-index stage in this
run is consistent with the large variation previously observed; this
does not establish a causal performance advantage.

**Earlier-build reference:** the older Windows Qt experimental build
reported 533/533 mapped SST opens and the standalone synthetic
compaction smoke passed twice (212/212 mapped). This clean-branch log
adds real Windows startup/sync/shutdown evidence, not a repetition of
the synthetic compaction test.

## Standalone regression source

`src/leveldb/db/win_block_index_mmap_smoke.cc` is intentionally **not**
included in the production Qt build. Link it as a separate Windows x86_64
console executable against the corresponding LevelDB static library.

Example (adjust build paths and linker libraries for the actual toolchain):

```bash
SRC=/path/to/PePe-core
BUILD=/path/to/win64-build
x86_64-w64-mingw32-g++ -std=c++11 -O2 \
  -DLEVELDB_PLATFORM_WINDOWS -DWINVER=0x0500 -D__USE_MINGW_ANSI_STDIO=1 \
  -I"$SRC/src/leveldb/include" -I"$SRC/src/leveldb" \
  "$SRC/src/leveldb/db/win_block_index_mmap_smoke.cc" \
  "$BUILD/src/leveldb/libleveldb.a" -lshlwapi -lws2_32 \
  -o "$BUILD/win_block_index_mmap_smoke.exe"
```

Run it in 64-bit Windows, with an **existing writable scratch parent** that
is not inside the real PEPEPOW data directory:

```powershell
$parent = Join-Path $env:TEMP "pepepow-mmap-test"
New-Item -ItemType Directory -Force -Path $parent | Out-Null
.\win_block_index_mmap_smoke.exe $parent
```

Never point the standalone tool at real wallet files or the live datadir.
The harness creates unique PID-namespaced child directories and deletes only
its scratch DB. The original experiment's initial scratch creation error was
corrected in the standalone harness using native `CreateDirectoryA`; no
production `Env::CreateDir` change is proposed in this review.

## Remaining risks and evaluation

- A mapped view may delay Windows deletion of an obsolete SST until all
  references have been released. The smoke passed synthetic compaction and
  final SST cleanup, not held-open-iterator deletion races.
- The inherited Windows `Env` path conversion uses fixed-size `MAX_PATH`
  buffers; this pre-existing limitation is outside this proposal.
- Failure-path and runtime tests should be reviewed separately, including
  forced mapping failures/limiter exhaustion, x86 behavior, and build flags.
- Startup elapsed time has varied substantially between trials:
  one opt-in LevelDB scan took about 18.9 seconds and another took about
  137.9 seconds. System cache and I/O conditions were not controlled, so
  **there is no established causal speed benefit**.
- Mapping is optional and disabled by default pending maintainer review.

Rollback: remove `-winmmapblockindex=1` (or set it to `0`) to use the
original `ReadFile` path immediately. Reindexing and wallet changes are
not required.

## Maintainer boundary

This is a proposed **independent Draft PR**, not a request to merge.
Do not merge it into `master` automatically and do not add it to Qt Draft
PR #2. The maintainer may review or cherry-pick the small commits separately.
