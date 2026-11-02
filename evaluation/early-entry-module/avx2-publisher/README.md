# AVX2 full-value witness publisher

Source `490cba34798fa24d8cf5fc8a72369adbfd0475f7`; hardware: AMD EPYC Zen 5 dev host. AVX2 selection checks host support and every authentic preparation image's complete XSAVE layout. AVX2 and SSE2 fallback both write all 128 header + 512 journal words, header first, before the unchanged marker. Independent snapshot reborrowing, complete scratch encoding, comparators and fixed cases remain. This changes witness publication, not production throughput.

Focused attempts are preserved: E0284 FAILED before tests; SIGXFSZ FAILED at the unchanged 128-MiB stderr bound after 128 observed passes; then PASS with 242 calibration passes/1 unchanged ignore, fmt and scoped strict Clippy. Both new controls passed in the latter two attempts; harness capture resolved expected-panic output overflow. A supplemental selector capture resolved the initial static coverage gap. Seven complete functions cover copy paths/selection; static counts establish neither executed cost nor restoration.

Native passed all four cases (4,136 calls; 4,072 observed; 4,056 sampled; 64 bypass). Strict20k FAILED at the unchanged cutoff: one failed cohort, 11 UNOBSERVED, zero pairs; the 32-row plan retains one FAILED and 31 UNOBSERVED. Separate80k passed 12 cohorts/288 pairs/576 children/139,872 full-state comparisons with zero mismatches. Candidate ranges: enabled 36,375–37,723; bypass 12,792–14,167; scheduled 14,121–37,756. Exactly 144 rows were ≤20k and 144 above, including every enabled row. All 288 matched candidate counts decreased versus retained v24: enabled−2,484; bypass−1,228; scheduled−1,228/−2,170/−2,484/−1,554 for loaded-true-disarm/loaded-false-arm/admitted-rearm/returned-disarm. Original counts, other fields and coverage stayed identical. These are step differences, not timing or causal production claims.

The 31-sample quiet decision remains NOT_ADMITTED (zero eligible); full-v24 remains NOT_RUN. The owner explicitly directed use of disjoint CPUs because quiet cannot be guaranteed. Operational admission was relaxed for one separate full-v25 correctness gate on 12 reserved CPUs; it is not quiet admission. All five commands PASS under unchanged deadlines. The audited census is 4,565 top-level +11 nested =4,576 raw passes/43 unchanged ignores; profiler 590/37, default calibration 237/1, ordinary 522/1 and serial 1,039. All 27 critical and 21 short-neighbor cases passed. Affinity/loads are recorded; external reservation is root-attested. No performance qualification follows.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

Reproduce from the exact clean source revision. Set ROOT, TOOLCHAIN, USER_HOME and CARGO_HOME to local paths; reserve one CPU per build/scientific command and use fresh child outputs. The receipt pins scripts, actual argv/env/artifacts and outcomes. In Bash:

```bash
cd "$ROOT"
mkdir -p "$ROOT/ignored/avx2" "$ROOT/target/evaluation/avx2"
args=(--root "$ROOT" --revision 490cba34798fa24d8cf5fc8a72369adbfd0475f7 --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME")
python3.9 -I -B evaluation/early-entry-module/ret-inline/build.py "${args[@]}" --output "$ROOT/ignored/avx2/build" --logs "$ROOT/target/evaluation/avx2/build"
python3.9 -I -B evaluation/early-entry-module/reproduce.py "${args[@]}" --output "$ROOT/ignored/avx2/native"
python3.9 -I -B evaluation/early-entry-module/state.py "${args[@]}" --output "$ROOT/ignored/avx2/strict"
python3.9 -I -B evaluation/early-entry-module/state_wide_80k.py "${args[@]}" --output "$ROOT/ignored/avx2/wide"
```

The scientific limits remain 20,000/80,000 steps, 15 seconds per pair and 2 seconds cleanup. Native execution permissions and hardware prerequisites remain. For full correctness reserve 12 CPUs, use the receipt's full environment (serial override for the last command), and run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-features --all-targets
cargo test -j 12 --workspace --no-fail-fast
cargo test -p liteinst-launch --tests -- --test-threads=1 --nocapture
```

Walls stay 180/180/180/900/180 seconds. The private owner/180-second inventories are separate from these bare commands. Static reproduction uses the same build and recorded objdump symbols/argv. Elapsed times and loads are not benchmarks. All 33 new CSVs are verbatim; [prior evidence](../binding-envelope/receipt.json) retains earlier failures without copying its CSVs. Receipt/packet size aims are advisory and never filter outcomes. No A4/A5 completion is claimed.
