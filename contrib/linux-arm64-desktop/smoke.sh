#!/bin/bash
set -euo pipefail
[ "$(uname -m)" = aarch64 ] || { echo 'Native aarch64 test required' >&2; exit 1; }
cd /artifact
sha256sum -c SHA256SUMS.txt
unset LD_LIBRARY_PATH QT_PLUGIN_PATH QT_QPA_PLATFORM_PLUGIN_PATH
work=$(mktemp -d)
mkdir "$work/bin"
for binary in PEPEPOWd PEPEPOW-cli PEPEPOW-tx PEPEPOW_qt; do
    readelf -h "/artifact/$binary" | grep -q 'AArch64'
    echo "ELF dependencies: $binary"
    readelf -d "/artifact/$binary" | grep NEEDED
    if ldd "/artifact/$binary" | grep -q 'not found'; then exit 1; fi
    if [ "$binary" != PEPEPOW_qt ]; then
        if readelf -d "/artifact/$binary" | grep -Eq 'Shared library: \[lib(boost|ssl|crypto|event|openlibm|db_cxx)'; then
            echo "Unexpected shared dependency in $binary" >&2; exit 1
        fi
        cp "/artifact/$binary" "$work/bin/$binary"
    fi
done
cd "$work/bin"
./PEPEPOWd -version | head -1
./PEPEPOW-cli -version | head -1
./PEPEPOW-tx -create >/dev/null
cleanup() {
    if [ -n "${datadir:-}" ]; then ./PEPEPOW-cli -regtest -datadir="$datadir" stop >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
wait_rpc() {
    for attempt in $(seq 1 90); do
        if ./PEPEPOW-cli -regtest -datadir="$datadir" getblockchaininfo > "$work/chain.json" 2>/dev/null; then
            grep -q '"chain": "regtest"' "$work/chain.json"
            return
        fi
        sleep 1
    done
    return 1
}
datadir="$work/daemon"
mkdir "$datadir"
./PEPEPOWd -regtest -datadir="$datadir" -pid="$work/daemon.pid" -server -listen=0 -dnsseed=0 -discover=0 -daemon
wait_rpc
./PEPEPOW-cli -regtest -datadir="$datadir" getwalletinfo >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" generate 3 >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" stop
for attempt in $(seq 1 60); do
    [ ! -e "$work/daemon.pid" ] && break
    sleep 1
done
[ ! -e "$work/daemon.pid" ] || { echo 'Daemon did not stop' >&2; exit 1; }
datadir="$work/qt"
mkdir "$datadir"
xvfb-run -a /artifact/PEPEPOW_qt -regtest -datadir="$datadir" -server -listen=0 -dnsseed=0 -discover=0 -choosedatadir=0 > "$work/qt.log" 2>&1 &
qt_pid=$!
if ! wait_rpc; then cat "$work/qt.log"; exit 1; fi
./PEPEPOW-cli -regtest -datadir="$datadir" getwalletinfo >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" stop
wait "$qt_pid"
datadir=
echo 'PASS: ARM64 checksums, standalone headless tools, regtest RPC/wallet/mining/shutdown and Qt/Xvfb'
