#!/usr/bin/env bash
# Distinguish runner DNS/HTTPS, registry pull and container DNS. No TLS bypass.
set -uo pipefail
case "${1:-}" in
  x86_64) mirrors=(archive.ubuntu.com security.ubuntu.com) ;;
  aarch64) mirrors=(ports.ubuntu.com) ;;
  *) echo 'Usage: network-preflight.sh x86_64|aarch64' >&2; exit 2 ;;
esac
failed=0
# Diagnostic only: do not silently replace the pinned distribution mirrors.
for host in azure.archive.ubuntu.com azure.ports.ubuntu.com; do
    if timeout 6 getent ahostsv4 "$host" > /dev/null; then
        echo "PASS optional Ubuntu Azure mirror DNS: $host"
        if [ "$host" = azure.ports.ubuntu.com ]; then altpath=ubuntu-ports; else altpath=ubuntu; fi
        if curl --fail --silent --show-error --location --max-time 15 --output /dev/null "https://$host/$altpath/dists/focal/InRelease"; then
            echo "PASS optional Ubuntu Azure mirror HTTPS: $host"
        else
            echo "INFO optional Ubuntu Azure mirror HTTPS unavailable: $host"
        fi
    else
        echo "INFO optional Ubuntu Azure mirror DNS unavailable: $host"
    fi
done
for host in "${mirrors[@]}" github.com; do
    if timeout 10 getent ahostsv4 "$host" > /dev/null; then
        echo "PASS runner DNS: $host"
    else
        echo "::error::INFRA_RUNNER_DNS: cannot resolve $host on runner" >&2
        failed=1
    fi
done
for host in "${mirrors[@]}"; do
    if [ "$host" = ports.ubuntu.com ]; then path=ubuntu-ports; else path=ubuntu; fi
    if curl --fail --silent --show-error --location --max-time 20 --output /dev/null "https://$host/$path/dists/focal/InRelease"; then
        echo "PASS runner HTTPS: $host"
    else
        echo "::error::INFRA_RUNNER_HTTPS: cannot fetch signed Ubuntu index from $host" >&2
        failed=1
    fi
done
if ! timeout 120 docker pull ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214 >/dev/null; then
    echo '::error::INFRA_REGISTRY: cannot pull pinned Ubuntu image' >&2
    exit 1
fi
for host in "${mirrors[@]}"; do
    if timeout 20 docker run --rm ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214 getent hosts "$host" > /dev/null; then
        echo "PASS container DNS: $host"
    else
        echo "::error::INFRA_CONTAINER_DNS: cannot resolve $host in Docker" >&2
        failed=1
    fi
done
if [ "$failed" -ne 0 ]; then
    echo 'Dependency/network preflight failed before compilation; see INFRA_* diagnostics.' >&2
    exit 1
fi
