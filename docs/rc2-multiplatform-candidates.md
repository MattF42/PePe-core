# v2.9.0.6 Optional candidate builds

The candidate workflows build the exact checked-out commit, never the synthetic
pull-request merge commit. Linux x86_64 and native ARM64 run their existing
Ubuntu 22.04 and 24.04 compatibility tests; Windows is cross-compiled and its
PE architecture and DLL imports are inspected. A cross-build is not Windows
GUI or wallet acceptance testing.

Candidate archives use `PEPEPOW-v<version>-<7charSHA>-test-<platform>` with
`.tgz` on Linux and `.zip` on Windows. Each includes the full source commit in
`BUILD-INFO.txt`; the workflow uploads the archive and its SHA256 manifest.
These are test artifacts, not official releases. A final `-release-` archive
must be rebuilt from the approved upstream commit, not renamed from a candidate.

The workflows are manually dispatchable. Expensive PR builds run after a PR
is marked ready, or when its `build-candidates` label is applied; documentation
only changes do not trigger those builds. The Windows dependency cache is keyed
by its build files and Dockerfile. Cache contents are not a substitute for
source hash verification.

The lightweight preflight distinguishes runner DNS/HTTPS, registry, and Docker
DNS failures before compilation. On the observed hosted runners, Ubuntu archive,
security, ports, and Azure mirror names failed to resolve on the runner itself;
GitHub DNS worked. Restore the runner's trusted DNS and Ubuntu mirror access,
or provide a verified pre-provisioned builder on a network-enabled runner.
Changing Docker networking alone did not resolve this. A passing preflight is
not evidence of a successful compile or runtime test.

Before public release, test the final Windows Qt wallet, daemon, CLI and tx on
Windows, including a basic wallet transaction. Record which Windows versions
were tested. Do not use private production keys in test artifacts.
