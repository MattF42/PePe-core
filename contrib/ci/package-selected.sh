#!/usr/bin/env bash
# Candidate by default; only manual official master builds may package a Release.
set -euo pipefail
if (( $# != 4 )); then
  echo "Usage: package-selected.sh OUTPUT_ROOT COMMIT_SHA PLATFORM DEST" >&2
  exit 2
fi
sha=$2
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "Expected a full source SHA" >&2; exit 2; }
test "$(git rev-parse HEAD)" = "$sha"
config=$(git show "$sha:configure.ac")
if printf '%s\n' "$config" | grep -Fxq 'define(_CLIENT_VERSION_IS_RELEASE, true)' &&
   [[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch &&
      "${GITHUB_REPOSITORY:-}" == MattF42/PePe-core &&
      "${GITHUB_REF:-}" == refs/heads/master ]]; then
  exec "$(dirname "$0")/package-release.sh" "$@"
fi
exec "$(dirname "$0")/package-candidate.sh" "$@"
