#!/bin/bash
set -euo pipefail
[ "$(uname -m)" = aarch64 ] || { echo 'Native aarch64 builder required' >&2; exit 1; }
export CCACHE_DIR=/tmp/pepe-ccache
mkdir -p /tmp/pepe-source /tmp/pepe-build "$CCACHE_DIR" /output
cp -a /source/. /tmp/pepe-source/
cd /tmp/pepe-source
# Berkeley DB 4.8 predates aarch64; update only its build-system architecture map.
python3 - <<'PY'
from pathlib import Path
p = Path('depends/packages/bdb.mk')
s = p.read_text()
needle = 'define $(package)_preprocess_cmds\n'
assert s.count(needle) == 1
p.write_text(s.replace(needle, needle + '  rm -f dist/config.sub dist/config.guess && cp $(BASEDIR)/config.sub $(BASEDIR)/config.guess dist/ && \\\n'))
PY
# Use the same repository depends libraries as existing ARM64 headless builds.
make -C depends -j4 HOST=aarch64-linux-gnu NO_QT=1 NO_UPNP=1 NO_ZMQ=1
# The headless depends config intentionally disables Qt and hides system pkg-config
# directories; permit the distribution's dynamic Qt for the desktop build.
cp depends/aarch64-linux-gnu/share/config.site /tmp/pepe-qt-config.site
python3 - <<'PY'
from pathlib import Path
p = Path('/tmp/pepe-qt-config.site')
s = p.read_text()
# Copy is outside the prefix, so replace its computed path with the real one.
s = s.replace('depends_prefix="`dirname ${ac_site_file}`/.."', 'depends_prefix="/tmp/pepe-source/depends/aarch64-linux-gnu"')
s = s.replace('with_protoc_bindir=$depends_prefix/native/bin', 'with_protoc_bindir=/usr/bin')
s = s.replace('export PKG_CONFIG_LIBDIR=$depends_prefix/lib/pkgconfig', 'export PKG_CONFIG_LIBDIR=$depends_prefix/lib/pkgconfig:/usr/lib/aarch64-linux-gnu/pkgconfig:/usr/share/pkgconfig')
p.write_text(s)
PY
./autogen.sh
cd /tmp/pepe-build
CONFIG_SITE=/tmp/pepe-qt-config.site /tmp/pepe-source/configure --host=aarch64-linux-gnu --prefix=/tmp/pepe-source/depends/aarch64-linux-gnu --with-gui=qt5 --with-qt-bindir=/usr/lib/qt5/bin --without-miniupnpc --disable-tests --disable-bench --disable-zmq CXXFLAGS='-O2 -g0'
make -C src -j4 qt/PEPEPOW_qt PEPEPOWd PEPEPOW-cli PEPEPOW-tx CXXFLAGS='-O2 -g0 -include deque -include condition_variable'
exec /source/contrib/linux-arm64-desktop/package.sh /tmp/pepe-source /tmp/pepe-build /output
