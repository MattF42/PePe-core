#!/bin/bash
set -euo pipefail
source_dir=${1:?source directory required}
build_dir=${2:?build directory required}
output_dir=${3:?output directory required}
mkdir -p "$output_dir"
tools_dir=$(mktemp -d)
trap 'rm -rf "$tools_dir"' EXIT
fetch() {
    local url=$1 file=$2 expected=$3
    curl -fsSL --retry 3 "$url" -o "$file"
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
    chmod +x "$file"
}
fetch https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage "$tools_dir/linuxdeploy-x86_64.AppImage" df908b19f1ed1cdafa79508d415aa12d6c56ce4d56d4149aa8c09286718706e5
fetch https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-x86_64.AppImage "$tools_dir/linuxdeploy-plugin-qt-x86_64.AppImage" cfc1055b2b9dbc08412b579f20990b7b41a17b61beaa5847dc9477c96c9e9617
fetch https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage "$tools_dir/appimagetool-x86_64.AppImage" e8c1169c4af66c3184d7ee110713d4be04befe671fa358e2c1591ee840553b03
fetch https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64 "$tools_dir/runtime-x86_64" 617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46
cat > "$tools_dir/pepepow.desktop" <<'DESKTOP'
[Desktop Entry]
Type=Application
Name=PEPEPOW Core
Exec=PEPEPOW_qt
Icon=pepepow
Categories=Office;Finance;
Terminal=false
DESKTOP
cp "$source_dir/contrib/linux-portable/pepepow-256.png" "$tools_dir/pepepow.png"
export APPIMAGE_EXTRACT_AND_RUN=1 QMAKE=/usr/bin/qmake ARCH=x86_64
cd "$tools_dir"
./linuxdeploy-x86_64.AppImage --appdir "$tools_dir/AppDir" --executable "$build_dir/src/qt/PEPEPOW_qt" --desktop-file "$tools_dir/pepepow.desktop" --icon-file "$tools_dir/pepepow.png" --plugin qt
for lib in libharfbuzz.so.0 libfontconfig.so.1 libfreetype.so.6 libSM.so.6 libICE.so.6 libssl.so.1.1; do
    cp -L "/usr/lib/x86_64-linux-gnu/$lib" "$tools_dir/AppDir/usr/lib/$lib"
done
ln -sf libssl.so.1.1 "$tools_dir/AppDir/usr/lib/libssl.so"
ln -sf libcrypto.so.1.1 "$tools_dir/AppDir/usr/lib/libcrypto.so"
cp -L /usr/lib/x86_64-linux-gnu/qt5/plugins/platforms/libqoffscreen.so "$tools_dir/AppDir/usr/plugins/platforms/libqoffscreen.so"
python3 - "$tools_dir/AppDir/AppRun" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]); s=p.read_text(); needle='source "$this_dir"/apprun-hooks/'
assert s.count(needle)==1
p.write_text(s.replace(needle,'export LD_LIBRARY_PATH="$this_dir/usr/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n\n'+needle))
PY
./appimagetool-x86_64.AppImage --runtime-file "$tools_dir/runtime-x86_64" "$tools_dir/AppDir" "$output_dir/PEPEPOW_qt.AppImage"
# Keep the historical executable name. The file remains an AppImage internally;
# users can launch it as ./PEPEPOW_qt with the same FUSE/extraction behavior.
mv "$output_dir/PEPEPOW_qt.AppImage" "$output_dir/PEPEPOW_qt"
chmod 755 "$output_dir/PEPEPOW_qt"
mkdir -p "$output_dir/bin"
for binary in PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do
    install -m 755 "$build_dir/src/$binary" "$output_dir/bin/$binary"
    strip --strip-all "$output_dir/bin/$binary"
done
cp "$source_dir/COPYING" "$output_dir/"
cat > "$output_dir/README.md" <<'DOC'
# PEPEPOW Linux x86_64 portable test package

This is a CI test build, not an official release. Run `./PEPEPOW_qt` in a graphical environment; the filename follows the historical wallet executable, but it internally contains an AppImage runtime. On systems without FUSE, use `APPIMAGE_EXTRACT_AND_RUN=1 ./PEPEPOW_qt`. The standalone `bin/PEPEPOWd`, `bin/PEPEPOW-cli`, and `bin/PEPEPOW-tx` can be copied individually; they require standard Linux system libraries but no bundled library directory. Standard desktop libraries including libGL and font configuration are required. Verify files with `sha256sum -c SHA256SUMS.txt`. Use backed-up data and test funds. Ubuntu 22.04/24.04 Xvfb tests do not establish real desktop or live-network behavior.
DOC
printf 'Source commit: %s\nCompiler: %s\n' "${PEPE_SOURCE_SHA:-unknown}" "$(g++ -dumpfullversion -dumpversion)" > "$output_dir/BUILD-INFO.txt"
(cd "$output_dir"; find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt; sha256sum -c SHA256SUMS.txt)
