#!/bin/bash
set -euo pipefail
# /source is a clean git archive; /output is writable by the caller.
mkdir -p /tmp/pepe-source /tmp/pepe-build /output
cp -a /source/. /tmp/pepe-source/
cd /tmp/pepe-source
./autogen.sh
cd /tmp/pepe-build
/tmp/pepe-source/configure --with-gui=qt5 --without-miniupnpc --disable-tests --disable-bench --disable-zmq CPPFLAGS=-I/opt/db4/include LDFLAGS=-L/opt/db4/lib CXXFLAGS='-O2 -g0'
# Build the GUI with its existing shared dependencies for linuxdeploy.
make -C src -j4 qt/PEPEPOW_qt CXXFLAGS='-O2 -g0 -include deque -include condition_variable'
# Keep glibc dynamic. Explicit archives isolate headless executables from the
# builder's shared third-party libraries; the group resolves Boost cross-references.
lib=/usr/lib/x86_64-linux-gnu
boost="-Wl,--start-group $lib/libboost_system.a $lib/libboost_filesystem.a $lib/libboost_program_options.a $lib/libboost_thread.a $lib/libboost_chrono.a $lib/libboost_atomic.a -Wl,--end-group"
make -C src -j4 PEPEPOWd PEPEPOW-cli PEPEPOW-tx \
    CXXFLAGS='-O2 -g0 -include deque -include condition_variable' \
    LDFLAGS='-L/opt/db4/lib -static-libstdc++' \
    BOOST_LIBS="$boost" BDB_LIBS=/opt/db4/lib/libdb_cxx-4.8.a \
    SSL_LIBS="$lib/libssl.a" CRYPTO_LIBS="$lib/libcrypto.a -ldl -pthread" \
    EVENT_PTHREADS_LIBS="$lib/libevent_pthreads.a" EVENT_LIBS="$lib/libevent.a -pthread" \
    OPENLIBM_LIBS=/usr/local/lib/libopenlibm.a
exec /source/contrib/linux-portable/package.sh /tmp/pepe-source /tmp/pepe-build /output
