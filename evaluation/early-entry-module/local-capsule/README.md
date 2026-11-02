# Local capsule — rejected

Candidate `5150a1d677a5ffd5e2e25dc5cbe53b24e4494d45`, tree `d2cdf1c9314007430166affa5478a673e6766f45`, on an AMD EPYC Zen 5 dev host. It retained successfully checked local physical predicates while keeping shared/normal, geometry, record and pending-owner checks fresh. **Rejected for increased step counts**; the whole change was reverted in `231264092453d04c8b6af1a75a0e274a31383aef`, restoring tree `502e7a9701714407bf0426fccfd8ff582c844d27` exactly.

- Focused formatting/library/Clippy checks passed: 592 tests, 37 unchanged ignores, one CPU. Six precommit images were recorded; this receipt has no revision, whole-tree freeze or postflight inventory. Committed applicability is separately reviewed.
- Default native correctness passed all four cases with prior counters.
- Strict 20k FAILED in the first enabled cohort: eleven cohorts UNOBSERVED, zero completed pairs, one FAILED/31 UNOBSERVED plan rows. Preparation passed 240 calibrations/one unchanged ignore. Return positions 9,768/19,304 increased +290/+406 over prior 9,478/18,898; this is partial-prefix arithmetic.
- Separate `qualification-feature-optional-entry-80k-v1` passed 12 cohorts/288 pairs/576 children/139,872 exact comparisons, zero mismatches. It retained 16 coverage rows and 32 controller handshakes. Candidate endpoints: 136 at most 20,000 steps, 152 above.
- Candidate static and full gates were NOT_RUN after rejection. Separate final-branch validation remains pending and receives no capsule credit here.

| Candidate mode | Step range | Matched increase |
|---|---:|---:|
| Enabled, 128 rows |39,046–40,394|+187 each|
| Bypass, 128 rows |14,425–15,800|+405 each|
| Scheduled, 32 rows |15,754–40,427|+187…+405|

All 288 matched candidate counts increased; all 288 originals were unchanged, with zero unmatched rows. Scheduled increases were +405 loaded-true-disarm, +205 loaded-false-arm, +187 admitted-rearm, +400 returned-disarm (eight each). This is cross-binary arithmetic, not timing or per-function causal attribution. Correctness PASS is preserved despite rejection. The revert also withdraws the capsule's two dedicated controls; all pre-capsule assertions/tests are restored literally.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

All 33 CSVs/69,720 bytes are literal: one strict plan and 32 wide plan/pair/coverage files. Native counters are JSON-only. Receipt hashes bind CLOSED metadata/reviews; raw logs stay private. The [prior receipt](../binding-envelope/receipt.json) retains earlier outcomes. Size aims never filter outcomes. Durations/load/affinity are operational, not performance or independent allocator witnesses.

To reproduce, use a clean candidate-revision checkout and the [bounded owner block](../binding-envelope/README.md): replace its revision with 5150 above and `binding-envelope-reproduction`/`binding-envelope-` stems with fresh `local-capsule-reproduction`/`local-capsule-`. Keep one reserved CPU, sequential one-attempt [native](../reproduce.py)/[strict](../state.py)/[80k](../state_wide_80k.py) from ROOT, 1,800/11,000s owners, 8 MiB captures, durable cleanup-before-read and failure retention. This is reproduction syntax, not an observed external launch.

Retain before/after allocated/apparent slot/ignored/target count-links inventory (30 CPU/180 wall seconds/256 MiB/64 KiB), ceilings 19,994,091,520/19,061,190,371 bytes and cumulative reserve 2,214,592,512. No retry/cache cleaning. All 640 words, pair 15s/cleanup 2s, strict 20k/separate 80k remain unchanged. The [public builder](../ret-inline/build.py) uses Python3.9 `-I -B` and `--root ROOT --revision REV --toolchain TOOLCHAIN --user-home USER_HOME --cargo-home CARGO_HOME --output ROOT/ignored/FRESH --logs ROOT/target/evaluation/FRESH` on one CPU; 120 CPU/180 wall/205 owner seconds, one job, 128 MiB file output (not memory).
