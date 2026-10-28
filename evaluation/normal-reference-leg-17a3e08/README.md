# Fresh-process ordinary-call reference collector

Revision `17a3e086f3f5bb46fbc19512620f75cc69bbab6c` adds
`ordinary-interval normal-reference-leg PHASE TRIAL LEG ...`. A process executes
exactly 24 original or 24 installed calls through the qualified 295-byte fenced
helper. Original processes allocate no profiler journal/controller; installed
processes retain all callback, stack, continuation, journal, Report and history
checks. This makes later randomized process order possible without restoring
patched code. The original 48-call collector remains a mandatory prerequisite.

All 30 release stages passed in 98.510 seconds on the
AMD EPYC Zen 5 dev host. Root authenticated all 76 owned stage receipts in the
complete prerequisite chain, with normal closure and zero rescues. Twelve new
Python controls and nine new Rust controls passed. The two new processes each
completed 12 helper calls and 24 returned cells; the installed process produced
24 confirmed records, 48 events, all 512 journal words, one Report and two
controller actions. Each leg executes exactly 4,800 original-body instructions,
780 conditional branches, 756 taken branches, 780 input-byte reads and 192 return
bytes under the fixed assembly model. These are semantic counts, not PMU counts.

Both complete 45-column, 24-row CSVs are retained. Their local sequence is 1–24;
original SDK fields remain absent. Phase/trial/leg come from the expected command
and must agree with every row and terminal record. Cross-process addresses,
generations and clocks are not equated. The population uses two input seeds,
lengths 1/64 and three repetitions, with two equal-length calls per helper.

Raw elapsed TSC ticks from this one functional run:

| Leg | Length | Calls | Fenced CALL enclosure R | Callback interval H |
| --- | ---: | ---: | ---: | ---: |
| Original | 1 | 12 | 46–140 | — |
| Original | 64 | 12 | 77–217 | — |
| Installed | 1 | 12 | 2124–8246 | 1349–6293 |
| Installed | 64 | 12 | 2061–3658 | 1286–2697 |

For each installed call, checked endpoints establish
`R = entry_gap + H + return_gap`. No zero span occurred; zero and equal endpoints
remain accepted and covered by controls. These ranges are uncalibrated and are
not a body-duration accuracy or throughput result. A future fresh-process
contrast includes configuration, cache and ASLR effects. Neither enclosure nor
callback interval is an independent same-call uninstrumented counterfactual.

The inherited native checks repeat 25 pairs, 50 children and 7,476 full-state
comparisons with zero mismatches. Reference-reader/store provenance and the
15-second-per-pair / 20,000-step-per-child limits remain unchanged.

Reproduce with Rust 1.97.1, GCC 11.5.0 and Python 3.12.15:

```sh
python3 -B tools/rapid-profiler/verify_normal_interval.py \
  --reference-exact --reference-work --reference-leg \
  --revision 17a3e086f3f5bb46fbc19512620f75cc69bbab6c \
  --raw "$PWD/ignored/NEW_REFERENCE_LEG_RUN" --toolchain "$TOOLCHAIN" \
  --user-home "$HOME" --cargo-home "$CARGO_HOME"
```

The exact recipe, tools, hardware and source/binary hashes are in `receipt.json`;
all top-level stage times and bounds are in `stages.csv`. Release optimization is
level 3 with no debug info and enabled assertions/overflow checks. Four
cooperatively reserved CPUs use hard AllowedCPUs assignment; unrelated host work
is not excluded. Each new process retains 20 CPU seconds, 30 wall seconds and
1 MiB output. Qualification calls are separate from any future study population.

All seven hand-back checks pass at the same source revision: default-parallel
workspace 3,061 passed, zero failed, 36 ignored in 337.516 seconds;
serial launch 1,039 passed in 124.565 seconds; staged allocation three
and prefixed pun 36. Formatting, strict workspace Clippy and all-target/all-feature
check pass. All seven historical admission/allocation regression names appear
exactly once as passes under the full 316-CPU harness default. `checks.csv`
records counts and log hashes. Independent source reviews and exact-commit
continuity cover producer, validators and recipe.

Two development records remain explicit. Initial strict Clippy rejected a
needless final `Option<&mut _>::as_deref_mut`; changing that final borrow to
`as_mut` preserves the same owner and validation predicate. The next strict run
passed. First release attempt passed all 30 functional stages, but root
accidentally nested two outer wrappers sharing one receipt name; that attempt
remains UNQUALIFIED_OUTER_RECEIPT_ALIAS. Its stage receipts are retained. After
removing the duplicate wrapper, fresh attempt 2 produced the clean receipt used
here. Neither record is hidden or relabelled.

This supports claim 4's functional validation. The four earlier whole timed
Exact37 campaigns remain FAILED with their unchanged 2 ms gate, as recorded in
[the progress receipt](../ordinary-exact-progress-20261028/README.md). This finite
collector does not qualify those campaigns. Calibration, uncertainty, matched
perf comparisons, broader workloads/browser coverage and full A5 remain open.
Raw logs, complete source manifests and captures stay under `ignored/`; only
compact raw rows, numerical summaries and exact receipts are committed.
