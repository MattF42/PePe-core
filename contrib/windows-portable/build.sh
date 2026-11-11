#!/usr/bin/env bash
set -euo pipefail
mkdir -p /tmp/pepe-source /tmp/pepe-build /tmp/pepe-ccache /output
export CCACHE_DIR=/tmp/pepe-ccache
cp -a /source/. /tmp/pepe-source/
cd /tmp/pepe-source
depends_args=(HOST=x86_64-w64-mingw32 NO_UPNP=1)
if [ -n "${PEPE_DEPENDS_CACHE:-}" ]; then
    mkdir -p "$PEPE_DEPENDS_CACHE/sources" "$PEPE_DEPENDS_CACHE/built"
    depends_args+=("SOURCES_PATH=$PEPE_DEPENDS_CACHE/sources" "BASE_CACHE=$PEPE_DEPENDS_CACHE/built")
fi
make -C depends -j4 "${depends_args[@]}"
./autogen.sh
cd /tmp/pepe-build
CONFIG_SITE=/tmp/pepe-source/depends/x86_64-w64-mingw32/share/config.site /tmp/pepe-source/configure \
    --host=x86_64-w64-mingw32 --prefix=/tmp/pepe-source/depends/x86_64-w64-mingw32 \
    --disable-tests --disable-bench --without-miniupnpc --disable-zmq CXXFLAGS='-O2 -g0'
make -C src -j4 qt/PEPEPOW_qt.exe PEPEPOWd.exe PEPEPOW-cli.exe PEPEPOW-tx.exe \
    CXXFLAGS='-O2 -g0 -include deque -include condition_variable'
for binary in PEPEPOW_qt PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do
    if [ "$binary" = PEPEPOW_qt ]; then source=src/qt/$binary.exe; else source=src/$binary.exe; fi
    install -m 755 "$source" "/output/$binary.exe"
    x86_64-w64-mingw32-strip --strip-all "/output/$binary.exe"
done
cp /tmp/pepe-source/COPYING /output/
printf 'Source commit: %s\nCompiler: %s\n' "${PEPE_SOURCE_SHA:-unknown}" "$(x86_64-w64-mingw32-g++ -dumpfullversion -dumpversion)" > /output/BUILD-INFO.txt
cat > /output/README.md <<'DOC'
# PEPEPOW Windows x86_64 candidate
Test-only build; not an official release. The Qt wallet and command-line tools are included together. Verify SHA256SUMS.txt. Cross-compilation and import inspection do not constitute Windows GUI testing.
DOC
/source/contrib/windows-portable/audit.sh /output
(cd /output && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
