At `32e97673211de73c70ef6f6ae5fa631a11b9b55a`, the required parallel workspace command passed: **3,613 passed, 0 failed, 37 ignored**. The neighbor integration harness passed all **101 tests**, including all 21 `short_neighbor` tests (the 20 existing tests and one new ownership control). Serial launch validation passed **1,039 tests**. Fmt, strict Clippy and all-feature/all-target checking passed. The current main ancestor is `44fab71b0f60927c3070b16af9f56a1d879154de`.

The failure was an address-placement collision, not just competing neighbor tests. A diagnostic run found the required selected trampoline at `0x7f4bcd51c0ba` inside an existing `PROT_NONE` interval `0x7f4bcc053000..0x7f4bd0000000`. This interval lies in an aligned 64 MiB region, consistent with a thread malloc arena. Placement failed before publication. Locking the neighbor tests could not keep an unrelated mapping out of a suffix-constrained destination near an anonymously placed source.

Each short fixture now reserves its own 4 GiB low-canonical virtual region with `MAP_FIXED_NOREPLACE`, placing the source at its midpoint. Calibration pages transfer directly from the reservation. The live planner receives the same two exact 8 KiB allocation windows; surrounding padding remains reserved. Separate fixtures cannot select the same region, and the short tests run concurrently. The legacy neighbor tests retain their crate-local lock. No workspace-wide serialization, allocation retry, fallback target, skipped native case or weakened assertion was added. All 462 pre-existing assertion macros in the reviewed files remain. The new control checks occupied-range refusal, overlapping transfers, and that padding teardown preserves transferred and reacquired pages.

Source bytes, suffix-derived targets, one-candidate search limits, both seeds, all 1,102 original heads, 2,204 installed and 2,204 retired comparisons, the separate engine bridge, full-state comparisons, hostile controls and child limits are unchanged. The existing observing-control, staged-drop and prefixed-pun allocation regressions also passed in the full workspace run. This supports claim 4's systematic tactic validation; it adds no broader publication or performance qualification.

All attempts remain recorded in [checks.csv](results-32e9767/checks.csv):

| Revision | Change | Parallel workspace result |
| --- | --- | --- |
| `92fff00c68f1e766b3fad54043657c0ea51a8041` | Short-only lock | Failed: 19 neighbor tests; 426.48 s |
| `e63a4ebbde721dbc471cddff1ab4c93911be7839` | Shared legacy/short lock | Failed: 19 neighbor tests; 509.81 s |
| `95b9cfc700def3b08f85e600fa96649e2ffc54ed` | Failure-only placement diagnostics | Separate 100-test neighbor run: 81 passed, 19 failed; 252.58 s |
| `739932cf5c49bceb06409281427221ed09a7fd19` | Private arenas | Build failed: test-only helper referenced by ordinary oracle binaries; Clippy also rejected an alignment expression |
| `32e97673211de73c70ef6f6ae5fa631a11b9b55a` | Correct test-module scope and equivalent alignment checks | Passed; 823.79 s |

The final serial launch command took 147.34 s. These are correctness-command wall times in unoptimized builds, not throughput measurements. The machine is the **AMD EPYC Zen 5 dev host**, with Rust 1.97.1, 16 reserved CPUs and `RUST_TEST_THREADS=316`. The final reservation was CPUs 3, 20, 27, 112, 146, 157, 162, 167, 171, 205, 230, 259, 275, 276, 284 and 307. Workspace load averages were 48.77/46.03/47.25 before and 69.19/66.82/58.33 afterward. Every command closed its process owner successfully with zero adopted/reaped descendants.

[receipt.json](results-32e9767/receipt.json) records revisions, hardware, build settings, CPU reservations, load averages, source hashes and review bindings. [harnesses.csv](results-32e9767/harnesses.csv) contains the actual completed outer Rust-test summaries, including both doctest segments. Five nested child summaries are recorded separately in the receipt and excluded from totals to avoid double counting. Two custom workspace harnesses completed separately and are excluded from Rust-test totals. [short-tests.csv](results-32e9767/short-tests.csv) records every short test's outcome. Raw logs and captures stay in `ignored/`.

Reproduce using [validate.py](validate.py) at the exact revision, with an offline Rust 1.97.1 toolchain/cache and a fresh output directory:

```sh
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 CARGO_NET_OFFLINE=true
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=0 CARGO_PROFILE_TEST_OPT_LEVEL=0
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
export LITEINST_EVALUATION=1
cpuset-alloc run --cores 16 --sample-s 1 --tag neighbor-parallel-reproduce -- \
  python3 -B evaluation/short-neighbor-parallel/validate.py \
  --revision 32e97673211de73c70ef6f6ae5fa631a11b9b55a \
  --output ignored/neighbor-parallel-reproduce
```

The script explicitly preserves 316 test threads under CPU affinity and runs `cargo test -j 16 --workspace --no-fail-fast`. Static checks and serial launch have 180-second limits; workspace has a prospectively declared 900-second limit. It records all five outcomes and does not retry. The separate diagnostic command was `RUST_TEST_THREADS=316 cargo test -j 16 --test neighbor_eviction_oracle -- --nocapture` at its recorded revision.

The unchanged live allocator requires the production image slots to be unmapped before planning; release and later acquisition are not atomic. This fixture placement relies on ordinary high top-down mappings avoiding the low namespace. Explicit-address interference, an occupied prescribed region, or virtual-address exhaustion still fails the test. No general reservation-adoption API or allocation guarantee is claimed.
