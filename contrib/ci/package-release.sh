#!/usr/bin/env bash
# Manual official-master release packaging. No tag or GitHub Release publication.
set -euo pipefail
if (( $# != 4 )); then
  echo "Usage: package-release.sh OUTPUT_ROOT COMMIT_SHA PLATFORM DEST" >&2
  exit 2
fi
root=$1
sha=$2
platform=$3
dest=$4
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected a full source SHA" >&2; exit 2; }
test "$(git rev-parse HEAD)" = "$sha"
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch &&
   "${GITHUB_REPOSITORY:-}" == MattF42/PePe-core &&
   "${GITHUB_REF:-}" == refs/heads/master ]] ||
  { echo "Release packaging requires a manual run on official master" >&2; exit 1; }
config=$(git show "$sha:configure.ac")
printf '%s\n' "$config" | grep -Fxq 'define(_CLIENT_VERSION_IS_RELEASE, true)' ||
  { echo "Release flag is not enabled in the exact source commit" >&2; exit 1; }
version_parts=()
for field in MAJOR MINOR REVISION BUILD; do
  number=$(printf '%s\n' "$config" |
    sed -n "s/^define(_CLIENT_VERSION_${field}, *\([0-9][0-9]*\))$/\1/p")
  [[ "$number" =~ ^[0-9]+$ ]] || { echo "Invalid version field: $field" >&2; exit 1; }
  version_parts+=("$number")
done
version=$(IFS=.; echo "${version_parts[*]}")
test "$version" = "2.9.0.6" || { echo "Unexpected release version $version" >&2; exit 1; }
case "$platform" in
  x86_64-w64-mingw32) ext=zip ;;
  x86_64-linux-gnu|aarch64-linux-gnu) ext=tgz ;;
  *) echo "Invalid platform $platform" >&2; exit 2 ;;
esac
"$(dirname "$0")/package-candidate.sh" "$root" "$sha" "$platform" "$dest"
candidate="$dest/PEPEPOW-v${version}-${sha:0:7}-test-${platform}.${ext}"
final="$dest/PEPEPOW-v${version}-${sha:0:7}-release-${platform}.${ext}"
test -f "$candidate"
test ! -e "$final"
mv -- "$candidate" "$final"
(cd "$dest" && sha256sum "$(basename "$final")" > SHA256SUMS.txt &&
  sha256sum -c SHA256SUMS.txt)
echo "Release package verified from exact source: $sha"
