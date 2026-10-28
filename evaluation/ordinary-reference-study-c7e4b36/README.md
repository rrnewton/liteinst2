# Fixed-work reference calibration and configuration comparison

At `c7e4b36b0a1f706aff7df578d39627895b70593e`, one planned release-build study completed **400 fresh study processes / 9,600 calls / 33,600 timestamp endpoints**, with no failed or omitted study process and no retry. This adds descriptive boundary-gap and observer-configuration evidence for A5; it does not establish duration accuracy or complete A5. The earlier strict 2 ms qualification remains three passes and two failures in five attempts.

The unchanged workload makes 24 calls per process, repeating two fixed inputs and lengths 1/64, twelve calls per length. Catalog seeds identify phase/trial/order; they do not vary the workload or create independent hardware samples. There are no hidden warmups. The fresh prerequisite and control processes are additional to these 400.

| Quantity | Observed result (TSC ticks) |
|---|---:|
| Calibration maximum entry gap Ue | 1,658 |
| Calibration maximum return gap Ur | 8,788 |
| Frozen total budget B = Ue + Ur | 10,446 |
| Holdout process maxima, p5 / median / p95 | 1,891 / 1,999 / 2,248 |
| Largest holdout gap | 2,619 |
| Paired installed-minus-original mean per call | 3,356.445 |
| Paired contrast p5 / median / p95 | 2,976.708 / 3,252.500 / 4,001.792 |
| Paired contrast minimum / maximum | 2,830.042 / 5,581.875 |

The first 100 installed processes calibrate Ue and Ur from all 2,400 calls. The script freezes those exact budget bytes before the next 100 installed holdout processes. All **100/100 holdout process maxima** fit B, with **zero entry, return or total exceedances** across all 2,400 holdout calls. This is empirical coverage for this run, not a confidence bound or an accuracy guarantee.

The final 100 blocks each run a fresh original and fresh installed process, with exactly 50 original-first and 50 installed-first blocks. A block contrast is `(sum(R_installed) - sum(R_original)) / 24`; each length stratum divides by 12. R is the fenced reference CALL enclosure. Its configuration contrast includes effects of instrumentation and setup on the enclosed calls; it is not isolated callback cost, bare-native overhead or a same-invocation counterfactual. The exact signed numerators, both length strata, all order-group means and nearest-rank quantiles remain in `summary.json`. No TSC-frequency conversion, confidence interval, PMU/perf comparison or body-only truth is inferred.

`execution.json` records the exact command template, revision, hardware, allocator version, four-CPU reservation **17/27/50/53**, study CPU **17**, source bindings and normal process closure. The run took **418.486 s** including fresh prerequisites and controls. Host load averages (1/5/15 minutes) were **32.87/32.12/32.52** before and **34.27/41.56/38.19** after. These are observations, not outcome filters. No build or test from this lane overlapped the timed study. The reservation is cooperative and provides no exclusive-host or real-time scheduling guarantee.

The binary used release opt-level 3, debug information 0, and enabled debug assertions/overflow checks. Full checks at the exact revision passed: **3,081 workspace tests, zero failures, 36 ignored**, plus two custom harnesses; **1,039 serial launch**, **3 staged-allocation**, **36 prefixed-pun** tests. All eight historical mapping/allocation regression cases passed in the default workspace run. `checks.csv` contains command durations and log hashes; these durations are validation costs, not performance estimates. The study freshly ran all **25 analysis/driver controls**, the full 30-stage reference prerequisite, its nested prerequisite chain, and the existing 1,696 old-Exact plus 1,736 reference native state comparisons.

Reproduce from a clean checkout of the recorded revision with stable Rust 1.97.1, Python 3.12.15, the tool identities in `receipt.json`, and the recorded cpuset allocator. Set REPO, TOOLCHAIN, USER_HOME, CARGO_HOME, PYTHON and CPUSET_ALLOCATOR to their local absolute paths. NEW_RUN must not exist. Run under an outer 1,200-second owned-process deadline, retaining the allocator output and load averages; the driver independently enforces its 1,200-second whole-study bound and 20 CPU-second / 30 wall-second / 1 MiB child bounds:

```sh
"$PYTHON" -B "$CPUSET_ALLOCATOR" run --cores 4 --sample-s 1 \
  --tag li2core-reference-study -- \
  "$PYTHON" -B "$REPO/tools/rapid-profiler/normal-work/reference_study.py" \
  --revision c7e4b36b0a1f706aff7df578d39627895b70593e \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`catalog.json` and `cases.json` define every planned process/call. `processes.csv` joins each process to its source, request, transcript and closure hashes and supplies the timestamp base and identity. Add its base to each offset in `endpoints.csv` to reconstruct all measured timestamps exactly; blank hook timestamps mean the original configuration. `budget.json` is the exact frozen calibration, and `receipt.json` is the driver's compact result. Raw transcripts and captures stay under ignored storage. Root separately replayed every strict raw row, verified all 400 owned process closures, reconstructed both CSVs and independently recomputed every calibration, holdout and contrast result. Source-only review grants no runtime evidence; these checks were executed by root.
