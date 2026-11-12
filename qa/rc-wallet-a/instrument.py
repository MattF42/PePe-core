#!/usr/bin/env python3
"""Instrument a disposable source archive for RC edge tests; never use production."""
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
if (root / '.git').exists() or not (root / 'src/wallet/wallet.cpp').is_file():
    raise SystemExit('requires a disposable source archive, not a Git checkout')

def replace(path, old, new):
    p = root / path
    text = p.read_text()
    if text.count(old) != 1:
        raise SystemExit(f'{path}: expected exactly one match for {old!r}')
    p.write_text(text.replace(old, new, 1))

(root / 'src/edge_test_hooks.h').write_text(r'''#ifndef PEPE_EDGE_TEST_HOOKS_H
#define PEPE_EDGE_TEST_HOOKS_H
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <string>
#include <thread>
inline void EdgeMark(const char* name) {
    const char* dir = std::getenv("PEPE_EDGE_DIR");
    if (dir && *dir) { std::ofstream f(std::string(dir) + "/" + name); f << "reached\n"; }
}
inline void EdgeBarrier(const char* stage) {
    const char* selected = std::getenv("PEPE_EDGE_PAUSE_STAGE");
    const char* dir = std::getenv("PEPE_EDGE_DIR");
    if (!selected || !dir || std::string(selected) != stage) return;
    EdgeMark(stage);
    const std::string path = std::string(dir) + "/release-" + stage;
    for (int i=0; i<12000; ++i) {
        if (std::ifstream(path).good()) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::abort();
}
#endif
''')
replace('src/wallet/wallet.cpp', '#include "wallet/wallet.h"', '#include "wallet/wallet.h"\n#include "edge_test_hooks.h"')
replace('src/wallet/wallet.cpp',
'''bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb)
{
    return pwalletdb->WriteTx(GetHash(), *this);
}''',
'''bool CWalletTx::WriteToDisk(CWalletDB *pwalletdb)
{
    const boost::filesystem::path fault = GetDataDir() / "edge-test-fail-wallet-write";
    if (mempool.exists(GetHash()) && boost::filesystem::exists(fault)) {
        LogPrintf("EDGE_TEST injected WriteTx failure txid=%s\\n", GetHash().ToString());
        EdgeMark("wallet-write-failed");
        return false;
    }
    return pwalletdb->WriteTx(GetHash(), *this);
}''')
replace('src/wallet/wallet.cpp',
'''        // Validate mempool acceptance before recording wallet spends. Otherwise''',
'''        const boost::filesystem::path rejectFault = GetDataDir() / "edge-test-reject-mempool";
        if (boost::filesystem::exists(rejectFault)) {
            boost::filesystem::remove(rejectFault);
            CMutableTransaction invalid(wtxNew);
            invalid.vout.at(0).nValue = -1;
            static_cast<CTransaction&>(wtxNew) = CTransaction(invalid);
            LogPrintf("EDGE_TEST invalid transaction for mempool rejection %s\\n", wtxNew.GetHash().ToString());
            EdgeMark("mempool-reject-injected");
        }
        // Validate mempool acceptance before recording wallet spends. Otherwise''')

print('Instrumented disposable wallet test source:', root)
