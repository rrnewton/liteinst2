# Ordinary-call reference endpoint collector

Revision `5d70e303958fb3282de0165343c5d289c3128cb0` adds
`ordinary-interval normal-reference-work`. It records fenced reference endpoints
around 24 original and 24 installed ordinary calls, then joins every installed
call to its callback endpoints, saved stack/continuation, complete journal,
Report and controller history. This supports claim 4's functional validation;
these measurements remain uncalibrated.

All 26 release qualification stages passed in 118.327 seconds on the AMD EPYC
Zen 5 dev host. The new collector completed 24 helper invocations, 48 returned
cells, one 24-record transfer, 48 journal events, one Report and two controller
actions. Every installed call was sampled and confirmed. Each leg performs
4,800 original-body instructions, 780 conditional branches, 756 taken branches,
780 input-byte reads and 192 return-word bytes under the fixed assembly model.
These are semantic counts, not PMU observations.

The fixed population repeats the two input seeds and lengths 1/64 three times;
each helper makes two equal-length calls sharing immutable input. Inputs are
shared across the original and installed legs. The original leg runs first on
the same actual thread and CPU. All 48 rows and their raw endpoints are retained
in `normal-reference-rows.csv`; original rows have no invented SDK fields.

The table below describes raw observations from this one functional run. `R`
is the fenced CALL enclosure and `H` is the interval between callbacks. Values
are elapsed TSC ticks; no frequency conversion, correction, uncertainty bound
or body-duration estimate is applied.

| Leg | Input length | Calls | R minimum–maximum | H minimum–maximum |
| --- | ---: | ---: | ---: | ---: |
| Original | 1 | 12 | 46–155 | — |
| Original | 64 | 12 | 108–155 | — |
| Installed | 1 | 12 | 1,984–7,936 | 1,225–5,781 |
| Installed | 64 | 12 | 2,124–2,992 | 1,333–2,077 |

For each installed call, checked endpoint arithmetic establishes
`R = entry_gap + H + return_gap`, with matching AUX values and the callback
interval inside its enclosure. This identity cannot measure perturbation inside
H. Original-before-installed execution is not a drift-controlled overhead
comparison. No timing-accuracy, performance-superiority or perf-comparison claim
follows from these ranges. Zero spans remain valid and are covered by controls;
none occurred in this run.

The inherited qualification repeats 17 ordinary pairs, four Exact37 pairs and
four reference pairs: 50 children and 7,476 architectural comparisons with zero
mismatches. The four reference pairs still check every actual reader/store,
helper instruction head and complete body, with 15 seconds per pair and 20,000
continuous steps per child. The 10 new Python and 13 Rust controls pass, as do
all inherited controls and abandonment cases. Root independently authenticated
all 72 stage receipts across the complete prerequisite chain, with normal
closure and no cleanup rescues.

Reproduce the full qualification with Rust 1.97.1, GCC 11.5.0 and Python 3.12.15:

```sh
python3 -B tools/rapid-profiler/verify_normal_interval.py \
  --reference-exact --reference-work \
  --revision 5d70e303958fb3282de0165343c5d289c3128cb0 \
  --raw "$PWD/ignored/NEW_REFERENCE_WORK_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The recorded run used release optimization level 3, no debug info, and enabled
assertions and overflow checks. Four cooperatively reserved CPUs had hard
AllowedCPUs assignment; unrelated host work was not excluded. Exact versions,
hardware, commands, source/binary hashes and stage durations are in
`receipt.json` and `stages.csv`. The new collector stage retains its 20 CPU-second,
30 wall-second and 1 MiB limits. Its observed process duration was 0.170 seconds,
including validation and output; that duration is not a throughput benchmark.

All seven required checks pass at the same source revision. The default-parallel
workspace has 3,052 passes, zero failures and 36 ignored tests in 332.073 seconds;
serial launch has 1,039 passes in 126.567 seconds. The staged-allocation and
prefixed-pun regressions pass, as do formatting, strict workspace Clippy and the
all-target/all-feature workspace check. All seven historical exec-admission and
allocation failure names pass under the 316-CPU harness default. `checks.csv`
records the exact counts, command times and log hashes. Independent source reviews and exact-commit continuity attestations
cover the producer, validators and recipe. No earlier predicate, population,
tolerance or native bound was relaxed. Cross-call chronology was made explicit
in the protocol before execution, retaining equal and zero endpoints.

The four earlier whole timed Exact37 session attempts remain FAILED in
[the existing progress receipt](../ordinary-exact-progress-20261028/README.md).
The unchanged 2 ms gate remains unresolved. This collector does not rerun or
qualify that campaign. Calibration, observer uncertainty, mixed requests,
concurrent reference callers, broader workloads/browser coverage and full A5
remain open. Raw logs and complete private captures stay under `ignored/`;
this directory contains compact rows and exact receipts.
