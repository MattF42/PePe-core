#!/usr/bin/env bash
# Assemble one candidate from an exact full source commit, never a release asset.
set -euo pipefail
root=${1:?package directory required}
sha=${2:?full source commit required}
platform=${3:?platform required}
dest=${4:?destination directory required}
[[ $sha =~ ^[0-9a-f]{40}$ ]] || { echo 'Expected a full 40-character source SHA' >&2; exit 2; }
config=$(git show "$sha:configure.ac")
version_parts=()
for field in MAJOR MINOR REVISION BUILD; do
    value=$(printf '%s\n' "$config" | sed -n "s/^define(_CLIENT_VERSION_${field}, *\([0-9][0-9]*\))$/\1/p")
    [[ $value =~ ^[0-9]+$ ]] || { echo "Cannot determine version $field from $sha" >&2; exit 1; }
    version_parts+=("$value")
done
version=$(IFS=.; echo "${version_parts[*]}")
case "$platform" in
  x86_64-linux-gnu)
    test -x "$root/PEPEPOW_qt"
    for bin in PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do test -x "$root/bin/$bin"; done
    extension=tgz ;;
  aarch64-linux-gnu)
    for bin in PEPEPOW_qt PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do test -x "$root/$bin"; done
    extension=tgz ;;
  x86_64-w64-mingw32)
    for bin in PEPEPOW_qt PEPEPOWd PEPEPOW-cli PEPEPOW-tx; do test -f "$root/$bin.exe"; done
    extension=zip ;;
  *) echo "Unknown platform: $platform" >&2; exit 2 ;;
esac
if find "$root" -type f \( -iname 'wallet.dat' -o -iname '*.log' -o -iname '*.key' -o -iname '*seed*' \) -print -quit | grep -q .; then
    echo 'Refusing to package a wallet, log, key or seed-like file' >&2; exit 1
fi
grep -Fx "Source commit: $sha" "$root/BUILD-INFO.txt"
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)
name="PEPEPOW-v${version}-${sha:0:7}-test-$platform.$extension"
if [ "$extension" = tgz ]; then
    tar -C "$root" -czf "$dest/$name" .
    tar -tzf "$dest/$name" >/dev/null
else
    (cd "$root" && zip -q -r "$dest/$name" .)
    unzip -tq "$dest/$name"
fi
(cd "$dest" && sha256sum "$name" > SHA256SUMS.txt && sha256sum -c SHA256SUMS.txt)
printf '%s\n' "$name"
