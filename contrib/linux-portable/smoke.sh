#!/bin/bash
set -euo pipefail
# Run in a disposable Ubuntu container with the package mounted at /artifact.
cd /artifact
sha256sum -c SHA256SUMS.txt
work=$(mktemp -d)
mkdir "$work/standalone" "$work/tx"
unset LD_LIBRARY_PATH
for binary in PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do
    if [ "$binary" = PEPEPOW-tx ]; then destination="$work/tx"; else destination="$work/standalone"; fi
    cp "/artifact/bin/$binary" "$destination/$binary"
    echo "ELF dependencies: $binary"
    readelf -d "$destination/$binary" | grep NEEDED
    if readelf -d "$destination/$binary" | grep -Eq '\((RPATH|RUNPATH)\)'; then
        echo "Unexpected RPATH/RUNPATH in $binary" >&2; exit 1
    fi
    while IFS= read -r lib; do
        case "$lib" in
            libc.so.6|libm.so.6|libpthread.so.0|librt.so.1|libdl.so.2|libanl.so.1|libresolv.so.2|libgcc_s.so.1|ld-linux-x86-64.so.2) ;;
            *) echo "Unexpected dynamic dependency in $binary: $lib" >&2; exit 1 ;;
        esac
    done < <(readelf -d "$destination/$binary" | sed -n 's/.*Shared library: \[\([^]]*\)\].*/\1/p')
    if ldd "$destination/$binary" | grep -q 'not found'; then exit 1; fi
done
cd "$work/standalone"
./PEPEPOW-cli -version | head -1
./PEPEPOWd -version | head -1
"$work/tx/PEPEPOW-tx" -create >/dev/null
cleanup() {
    if [ -n "${datadir:-}" ]; then ./PEPEPOW-cli -regtest -datadir="$datadir" stop >/dev/null 2>&1 || true; fi
    rm -rf "$work"
}
trap cleanup EXIT
wait_rpc() {
    local attempt
    for attempt in $(seq 1 60); do
        if ./PEPEPOW-cli -regtest -datadir="$datadir" getblockchaininfo > "$work/chain.json" 2>/dev/null; then
            grep -q '"chain": "regtest"' "$work/chain.json"
            return
        fi
        sleep 1
    done
    return 1
}
datadir="$work/daemon"
mkdir -p "$datadir"
./PEPEPOWd -regtest -datadir="$datadir" -pid="$work/daemon.pid" -server -listen=0 -dnsseed=0 -discover=0 -daemon
wait_rpc
./PEPEPOW-cli -regtest -datadir="$datadir" getwalletinfo >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" generate 3 >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" stop
for attempt in $(seq 1 60); do
    [ ! -e "$work/daemon.pid" ] && break
    sleep 1
done
[ ! -e "$work/daemon.pid" ] || { echo 'Daemon did not shut down' >&2; exit 1; }
# AppImage extraction avoids requiring FUSE in CI. Xvfb supplies a real X backend.
cd "$work"
/artifact/PEPEPOW_qt --appimage-extract >/dev/null
cd "$work/standalone"
datadir="$work/qt"
mkdir -p "$datadir"
xvfb-run -a "$work/squashfs-root/AppRun" -regtest -datadir="$datadir" -server -listen=0 -dnsseed=0 -discover=0 -choosedatadir=0 > "$work/qt.log" 2>&1 &
qt_pid=$!
if ! wait_rpc; then cat "$work/qt.log"; exit 1; fi
./PEPEPOW-cli -regtest -datadir="$datadir" getwalletinfo >/dev/null
./PEPEPOW-cli -regtest -datadir="$datadir" stop
wait "$qt_pid"
datadir=
echo 'PASS: checksum, standalone ELF audit and transaction tool, daemon regtest RPC, wallet, mining and Qt/Xvfb startup'
