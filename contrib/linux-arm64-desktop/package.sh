#!/bin/bash
set -euo pipefail
source_dir=${1:?source directory required}
build_dir=${2:?build directory required}
output=${3:?output directory required}
mkdir -p "$output/lib" "$output/plugins/platforms" "$output/plugins/imageformats"
for binary in PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do
    install -m 755 "$build_dir/src/$binary" "$output/$binary"
    strip --strip-all "$output/$binary"
done
install -m 755 "$build_dir/src/qt/PEPEPOW_qt" "$output/PEPEPOW_qt"
strip --strip-all "$output/PEPEPOW_qt"
# DT_RPATH is transitive: it also resolves dependencies loaded by Qt plugins.
patchelf --force-rpath --set-rpath '$ORIGIN/lib' "$output/PEPEPOW_qt"
for plugin in libqxcb.so libqoffscreen.so; do
    cp -L "/usr/lib/aarch64-linux-gnu/qt5/plugins/platforms/$plugin" "$output/plugins/platforms/"
done
for plugin in /usr/lib/aarch64-linux-gnu/qt5/plugins/imageformats/*.so; do
    [ -e "$plugin" ] || continue
    cp -L "$plugin" "$output/plugins/imageformats/"
done
cat > "$output/qt.conf" <<'QTCONF'
[Paths]
Plugins=plugins
QTCONF
# QtNetwork loads OpenSSL by name at runtime rather than declaring it in NEEDED.
cp -L /usr/lib/aarch64-linux-gnu/libssl.so.1.1 "$output/lib/libssl.so.1.1"
cp -L /usr/lib/aarch64-linux-gnu/libcrypto.so.1.1 "$output/lib/libcrypto.so.1.1"
python3 - "$output" <<'PY'
import os, pathlib, shutil, subprocess, sys
root = pathlib.Path(sys.argv[1])
inputs = [root / 'PEPEPOW_qt', *root.glob('plugins/*/*.so'), *root.glob('lib/*.so*')]
# Leave glibc and compiler runtime on the target host. Qt and plugin dependency
# closure is bundled; copy by SONAME so the loader can find each object.
system = {'libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1',
          'libresolv.so.2','libutil.so.1','libanl.so.1','libgcc_s.so.1',
          'libstdc++.so.6','ld-linux-aarch64.so.1'}
for obj in inputs:
    result = subprocess.run(['ldd', str(obj)], text=True, capture_output=True, check=True)
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[1] == '=>':
            name, path = fields[0], fields[2]
            if path == 'not':
                raise SystemExit(f'{obj}: missing dependency: {line}')
            if name not in system:
                if not os.path.isabs(path):
                    raise SystemExit(f'{obj}: unexpected library path: {line}')
                destination = root / 'lib' / name
                if not destination.exists():
                    shutil.copyfile(path, destination)
                    destination.chmod(0o755)
PY
cp "$source_dir/COPYING" "$output/"
cat > "$output/README.md" <<'DOC'
# PEPEPOW Linux ARM64 desktop test package

Unofficial RC test build. Run `./PEPEPOW_qt` from this extracted directory on an ARM64 Linux desktop; keep `qt.conf`, `lib/` and `plugins/` beside it. The daemon, CLI and transaction tool are individual native executables. Verify with `sha256sum -c SHA256SUMS.txt`. Standard glibc, libstdc++, graphics and desktop services remain host requirements. Use test funds and backups.
DOC
printf 'Source commit: %s\nBuild architecture: %s\nCompiler: %s\n' "${PEPE_SOURCE_SHA:-unknown}" "$(uname -m)" "$(g++ -dumpfullversion -dumpversion)" > "$output/BUILD-INFO.txt"
(cd "$output" && find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
