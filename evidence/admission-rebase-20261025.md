# Admission replay onto the extended core

Recorded 2026-10-25 13:05:13 EDT. Validated source:
`af9f2cf9d87a66847c9d2775a0ab350ea9167cf0`, descended from core
`6e99b849513799a35e6be3827ad484e4c5521e6d`.

The accepted B0/B1 stack was replayed onto this core revision. Workspace
membership retains both core tools and adds both admission crates. Core's
sanitized provenance text was retained. Core sources and contracts are unchanged.
The only subsequent adapter change handles the new `PlanKind::PrefixedPun`
variant in an exhaustive match; the existing private constructor still requires
a literal two-byte CPUID generalized pun. No new tactic is implicitly accepted.
Independent replay review approved this exact source revision.

The supported scope and correctness obligations remain those in the
[B1 receipt](admission-b1-20261025.md). That receipt's measurements remain tied
to its original source; they are not new-core performance measurements. No
tests, assertions, comparators, tolerances, ignore lists or gates changed in
this replay.

All four required checks passed on a clean tracked source tree, with four build
jobs, four test threads, incremental compilation disabled, offline resolution
and one target directory:

| Command | Exit | Seconds |
| --- | ---: | ---: |
| `cargo fmt --check` | 0 | 1.016 |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | 0 | 4.023 |
| `cargo test --workspace` | 0 | 275.834 |
| `cargo check --workspace --all-features --all-targets` | 0 | 3.721 |

Outer workspace harness totals: **730 passed, zero failed, four pre-existing
ignored**. Five successful nested core subprocess summaries are excluded from
that total. A separate sequential rerun of the checkpoint, page-gate,
concurrent-control and concurrent-gate test binaries passed **50 tests, zero
failed or ignored**. This includes the independent original-code GPR/flags/full
XSTATE/stack comparisons, interpreter entry, concurrent exactly-once admission,
cross-page fetches, real saved returns into NX pages and bounded cleanup.

Private logs, binary identities and source hashes remain under the ignored
relative directory
`target/li2adm-evidence/af9f2cf9d87a-required-20261025T170010Z/`.
The earlier compile refusal at replay tip `6578b22` is retained separately; it
is not represented as a pass. No raw logs or private host details are published.

| Capture | SHA-256 |
| --- | --- |
| Exact source/log `manifest.json` | `1db862484d6fdca299562306b62ffbfc67fab8c849cf6f18ea182200692f6a17` |
| Native rerun `native-validation.json` | `42c03b6743778ae9daecc8ada3da24a8a50e1fbc060c3524f609de2154934a24` |
