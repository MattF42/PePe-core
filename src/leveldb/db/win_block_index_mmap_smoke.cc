// Isolated Windows-only regression test for PEPEPOW's opt-in block-index mmap.
// Compile/link against the project's Windows x86_64 LevelDB library. This
// source is intentionally not part of the production Qt build.
// Never point this test directly at a wallet or chain data directory.
#if !defined(_WIN32) && !defined(WIN32)
#error This standalone regression test requires Windows.
#endif

#include "leveldb/db.h"
#include "leveldb/env.h"
#include "leveldb/options.h"
#include "leveldb/iterator.h"

#include <process.h>
#include <windows.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {

bool Check(const leveldb::Status& s, const std::string& operation) {
    if (s.ok()) return true;
    std::cerr << "FAIL " << operation << ": " << s.ToString() << "\n";
    return false;
}

// The vendored Windows LevelDB Env::CreateDir appends a trailing
// backslash before recursively creating directories. On some Windows paths
// this causes an extra CreateDirectory attempt after the directory already
// exists (ERROR_ALREADY_EXISTS). Create the isolated scratch directory using
// the native API without a trailing separator; leave the production Env alone.
bool CreateScratchDir(const std::string& name, const char* label) {
    std::string native = name;
    for (size_t i = 0; i < native.size(); ++i) {
        if (native[i] == '/') native[i] = '\\';
    }
    if (::CreateDirectoryA(native.c_str(), NULL)) return true;
    const DWORD error = ::GetLastError();
    std::cerr << "FAIL create " << label << ": " << native
              << " (Win32 error " << static_cast<unsigned long>(error) << ")\n";
    return false;
}

bool IsTableFile(const std::string& name) {
    const std::string::size_type p = name.rfind('.');
    if (p == std::string::npos) return false;
    const std::string ext = name.substr(p);
    return ext == ".ldb" || ext == ".sst";
}

bool RunCase(const std::string& parent, const std::string& mode, bool use_mmap) {
    leveldb::Env* env = leveldb::Env::Default();
    // Only create/destroy a fresh, PID-namespaced subdirectory of the provided
    // scratch parent. Refuse to touch it if it already exists.
    const std::string root = parent + "/pepe-mmap-smoke-" + mode +
                             "-" + std::to_string(_getpid());
    const std::string blocks = root + "/blocks";
    const std::string dbname = blocks + "/index";
    if (env->FileExists(root)) {
        std::cerr << "FAIL scratch directory already exists: " << root << "\n";
        return false;
    }

    if (!CreateScratchDir(root, "scratch root") ||
        !CreateScratchDir(blocks, "blocks directory") ||
        !CreateScratchDir(dbname, "scratch index")) {
        return false;
    }

    leveldb::Options options;
    options.create_if_missing = true;
    options.paranoid_checks = true;
    options.compression = leveldb::kNoCompression;
    options.write_buffer_size = 64 * 1024;
    options.max_open_files = 64;

    leveldb::SetWindowsBlockIndexMmapEnabled(use_mmap);
    leveldb::DB* db = NULL;
    if (!Check(leveldb::DB::Open(options, dbname, &db), "open scratch DB")) {
        return false;
    }

    bool ok = true;
    const int kCount = 6000;
    for (int round = 0; round < 3 && ok; ++round) {
        for (int i = 0; i < kCount; ++i) {
            const std::string key = "key-" + std::to_string(i);
            const std::string value = std::string(512, static_cast<char>('A' + round))
                                      + "-" + std::to_string(i);
            if (!Check(db->Put(leveldb::WriteOptions(), key, value),
                       "put scratch key")) {
                ok = false;
                break;
            }
        }
        if (ok) db->CompactRange(NULL, NULL);
    }

    // Reads must remain correct after compaction and across table-cache reuse.
    for (int i = 0; i < kCount && ok; i += 17) {
        const std::string key = "key-" + std::to_string(i);
        const std::string expected = std::string(512, 'C') + "-" + std::to_string(i);
        std::string got;
        ok = Check(db->Get(leveldb::ReadOptions(), key, &got),
                   "get scratch key") && got == expected;
        if (!ok) std::cerr << "FAIL value mismatch for " << key << "\n";
    }

    // Each live table should appear exactly once in the on-disk directory.
    // Catch obsolete SST files silently left behind by failed Windows deletion
    // while a view is still mapped.
    unsigned long live = 0;
    for (int level = 0; level < 7 && ok; ++level) {
        std::string value;
        if (!db->GetProperty("leveldb.num-files-at-level" + std::to_string(level),
                             &value)) {
            std::cerr << "FAIL num-files-at-level" << level << "\n";
            ok = false;
        } else {
            live += std::strtoul(value.c_str(), NULL, 10);
        }
    }
    std::vector<std::string> children;
    if (ok) ok = Check(env->GetChildren(dbname, &children), "enumerate tables");
    unsigned long disk = 0;
    for (size_t i = 0; i < children.size(); ++i) {
        if (IsTableFile(children[i])) ++disk;
    }
    if (ok && live != disk) {
        std::cerr << "FAIL obsolete SST cleanup: live=" << live
                  << " disk=" << disk << "\n";
        ok = false;
    }

    const leveldb::WindowsBlockIndexMmapStats stats =
        leveldb::GetWindowsBlockIndexMmapStats();
    if (use_mmap && (stats.mapped == 0 || stats.attempts < stats.mapped)) {
        std::cerr << "FAIL mmap not confirmed: attempts=" << stats.attempts
                  << " mapped=" << stats.mapped << "\n";
        ok = false;
    }

    delete db;
    db = NULL;
    leveldb::SetWindowsBlockIndexMmapEnabled(false);

    // Delete only the unique scratch DB we created. Report errors rather than
    // retrying or attempting to clean unrelated user-supplied paths.
    if (!Check(leveldb::DestroyDB(dbname, options), "destroy scratch DB")) ok = false;
    if (!Check(env->DeleteDir(blocks), "remove scratch blocks directory")) ok = false;
    if (!Check(env->DeleteDir(root), "remove scratch root")) ok = false;

    std::cout << (ok ? "PASS " : "FAIL ") << mode
              << " live_tables=" << live << " disk_tables=" << disk
              << " mmap_attempts=" << stats.attempts
              << " mapped=" << stats.mapped << "\n";
    return ok;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 || !argv[1][0]) {
        std::cerr << "Usage: win_block_index_mmap_smoke.exe "
                     "<existing scratch parent directory>\n";
        return 2;
    }
    leveldb::Env* env = leveldb::Env::Default();
    if (!env->FileExists(argv[1])) {
        std::cerr << "Scratch parent directory must already exist.\n";
        return 2;
    }
    if (!RunCase(argv[1], "readfile", false)) return 1;
    if (!RunCase(argv[1], "mmap", true)) return 1;
    std::cout << "PASS Windows block-index mmap compaction regression\n";
    return 0;
}
