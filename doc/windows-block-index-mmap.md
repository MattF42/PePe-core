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

**Provenance limit:** the Windows executable originated from the earlier
`perf/startup-win-mmap` experimental branch. The mmap implementation and
smoke source copied to this isolated branch are byte-for-byte identical to
those tested sources, but a fresh full Qt build directly from this clean
review branch has **not** been independently verified yet. Do not describe
this isolated branch's build or CI as PASS without running it.

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
