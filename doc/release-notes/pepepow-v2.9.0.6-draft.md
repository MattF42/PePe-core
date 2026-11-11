# PEPEPOW Core v2.9.0.6 — DRAFT release notes

> **Optional Upgrade — draft candidate only.** Official release and final assets are not yet available. Changes A/B/C have been selected by the Owner for inclusion; do not imply post-release edge testing has occurred.

## Highlights

- **Faster Windows Qt wallet:** previously merged improvements reduce large-wallet GUI stalls during chain catch-up; block-index read-only mmap remains optional and disabled by default (upstream #38/#39).
- **Masternodes:** clearer status, refreshing/copying in Qt, collateral tier display and defensive ping/Recovery validation without an intended protocol or quorum change (fork #4–#7).
- **Wallet usability:** Qt Send All, safe bounded UTXO consolidation, stale selection handling and clearer Coin Control checkboxes/subtotals (fork #8/#9/#14).
- **Qt appearance:** improved splash screen readability and default settings (fork #10/#14).
- **Linux distributions:** one `.tgz` for x86_64 and one for ARM64, each including `PEPEPOW_qt`, `PEPEPOWd`, `PEPEPOW-cli` and `PEPEPOW-tx` (fork #12/#13 staged by #15). Qt executable keeps its traditional name.

## RC testing

- **Linux x86_64:** [build and Ubuntu 22.04/24.04 tests PASS](https://github.com/edisontw/PePe-core/actions/runs/42864061348); Owner reports Qt/daemon/CLI and transaction sending work.
- **Linux ARM64:** [native build and Ubuntu 22.04/24.04 tests PASS](https://github.com/edisontw/PePe-core/actions/runs/42864061217); four running ARM64 nodes now report around 45 ENABLED versus 47 observed on other nodes. These are observations, not controlled same-height proof.
- **UTXO consolidation:** Owner passed ordinary interruption/restart. A DB-write fault test reproduced incorrect successful RPC reporting; v2.9.0.6 includes the preliminary error-with-txid mitigation, with follow-up live testing deferred. Transaction persistence under actual disk failure is not atomic/guaranteed.
- **Qt shutdown / Recovery:** the consolidation worker shutdown mitigation passed four controlled cases; Recovery orphan guard passed 22 assertions. The Owner elected inclusion without more pre-release edge tests.
- **ARM64 physical Qt Desktop:** untested; Owner accepts this as a non-blocking limitation.
- **Windows:** the earlier large-wallet fix passed manual testing, but this combined v2.9.0.6 RC still needs exact-source Windows build/runtime acceptance.

## Release scope and validation

This Optional version carries the selected wallet A warning, Qt consolidation B worker shutdown fix, and Recovery C orphan-reply guard. It is not intended as a mandatory hard fork or a network protocol change; maintainers must verify the final diff.

Exact A+B+C Linux candidate builds and Windows integrated binary acceptance remain pending. Experimental fault-injection hooks, test-only logs and internal diagnostics are not part of the public package.

## Upgrade and safety notes

Back up `wallet.dat` and fully stop the wallet before replacing binaries. Do not test large UTXO consolidations with irreplaceable funds. No mandatory consensus change is intended, but final OPTIONAL classification requires checking the approved source diff.

**Not published:** final release SHA/tag, official binaries, download links and SHA256 are still pending. Release only in [MattF42/PePe-core](https://github.com/MattF42/PePe-core), after maintainer approval and fresh builds.

[Current release checklist](../pepepow-v2.9.0.6-rc1-release-checklist.md)