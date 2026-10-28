# Bare-native caller/child comparison

Revision `a39caa7c7e2e372aa1c07194f9758101b263ecbb` adds a separately
qualified native call route and compares it with the guarded original SDK
and K1/K10/K24 consumers. All 65 release processes completed the same 1,536
root calls, for 99,840 roots total. The 121-stage recipe passed, including
1,356 new full-state comparisons across four native-call pairs. This supports
claim 4's systematic qualification; the full A5 performance gate remains open.

The primary measurement encloses fork through terminal wait4. Ten measured
blocks supply paired native/mode ratios; three predetermined warmup blocks
remain in the raw data. Reported cost ratios are mode/native geometric means.
Intervals are conditional 95% Student t9 intervals on paired log ratios.

| Consumer | Process-time ratio to native | Conditional 95% interval |
| --- | ---: | ---: |
| Guarded original SDK | 394.29× | 367.87–422.59× |
| K1 | 393.74× | 374.56–413.91× |
| K10 | 405.05× | 380.91–430.72× |
| K24 | 397.58× | 372.83–423.98× |

Native process time averaged 5.833 ms, with measured observations from
5.382 to 6.666 ms. SDK-mode averages were 2.292–2.361 seconds. The large cost
also occurs in the guarded original SDK route. The earlier comparison against
that route therefore measured only the additional cost relative to an already
expensive consumer. These results include source/input validation, SDK state
checks, retirement/drains/Reports and export; they do not isolate hook cost.
Native retains its fixed ABI stub and extra setup validation. No calibrated
clock accuracy, hardware-counter accuracy or general workload result follows.

`trials.csv` retains all clock endpoints, process wall times, wait4 CPU fields
and functional summaries. `statistics.json` retains all paired ratios and six
metric families. No outliers, short samples or failures were removed or
replaced; the complete cohort is a fresh run on the stated revision.
`receipt.json` records source/tool/artifact hashes, hardware, profile, command,
bounds and closure. `native-pairs.csv` and `stages.csv` record qualification.
Detailed transcripts and captures remain private under `ignored/`.

The hardware was the **AMD EPYC Zen 5 dev host**, observed family 26, model 17,
stepping 0. Rust/Cargo were stable 1.97.1 and GCC was 11.5.0. Rust used release
opt3, debug0, assertions and overflow checks enabled; C used O3. Compiler jobs
were capped at four. The campaign used an allocator-reported four-CPU
reservation, with each timed consumer pinned to one CPU. This is not proof of
exclusive host isolation. The operational campaign duration was 205.000 s.

At the stated revision, set `TOOLCHAIN`, `CARGO_HOME` and `CPUSET_ALLOC` to the
installed toolchain, Cargo cache and CPU allocator. From the repository root:

```sh
"$CPUSET_ALLOC" run --cores 4 --tag li2core-tree-native -- \
  python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision a39caa7c7e2e372aa1c07194f9758101b263ecbb \
  --raw "$PWD/ignored/NEW_NATIVE_COMPARISON" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing --cache-work \
  --counter-probe --call-tree --tree-population --tree-native-baseline
```

Every timing subject retains the 20 CPU-second, 30 wall-second and 1 MiB
limits. Both process owners must close normally with ECHILD and zero rescues;
expected rescues occur only inside the dedicated negative timer controls.
The native ABI qualifier retains the full GPR/flags/XSAVE/data/unmasked-stack
comparator, its 15-second absolute pair deadline and 20,000-step limit.

Three earlier attempts remain failed in `failed-attempts.json`: a native clock
bracket refusal; a retained-log name collision before timing; and a negative
control whose shared process group made descendant adoption race. The fixes
add a thread-clock query before the reported process-clock query, use complete
campaign-relative log names, and detach the closed-output test child before
its timeout. All previous positive-span, ordering, cleanup and resource checks
remain. No observation from those attempts enters this cohort.

The separate accounting diagnostic is reproducible with:

```sh
python3 -B evaluation/tree-native-a39caa7/reproduce-clock-limit.py \
  --output "$PWD/ignored/NEW_CLOCK_PROBE"
```

Its C source, 24 raw observations and compact receipt are included. Under the
finite CPU limit, 10 of 11 adjacent unrefreshed process-clock observations were
equal; all 11 refreshed pairs advanced. Phase-zero `thread=0` means that clock
was not queried. The source mechanism is documented in upstream Linux v7.1.3
[`cpu_clock_sample_group`](https://github.com/gregkh/linux/blob/v7.1.3/kernel/time/posix-cpu-timers.c)
and [`task_sched_runtime`](https://github.com/gregkh/linux/blob/v7.1.3/kernel/sched/core.c).
This diagnostic does not establish universal freshness, timing accuracy or
byte-equivalence with the deployed vendor kernel. The additional thread query
is included symmetrically in all new SDK/native clock brackets; earlier
measurements retain their original sampling method.

All seven repository checks passed at the same source revision (`gates.json`):
workspace 2,852 passed / 0 failed / 12 ignored in 333.670 s, with the full
316-CPU affinity and no test-thread override; serial launch 1,039/0/0 in
126.438 s; staged allocation 3/0/0; prefixed pun 36/0/0; formatting, strict
workspace Clippy and all-feature/all-target check. These durations are
operational. The workspace total excludes five nested child summaries and
includes every independent rustdoc suite. Its increase from 2,842 is exactly
six NativeCall calibrations and four collection controls. Source review caught
an initial plan that double-counted the custom non-libtest harness; no test
was removed. A separate closed-log comparison confirms those two target deltas
and unchanged counts for every other target.

The same seven checks also passed after merging main at
`695f1ef9af953a2a8071600a218453fb0473212e` (`merged-gates.json`): workspace
2,852/0/12 in 331.366 s; serial launch 1,039/0/0 in 124.074 s; staged
allocation 3/0/0 and prefixed pun 36/0/0. Default parallelism, limits and
comparators remain unchanged, with normal closure and zero rescues. All 170
native campaign inputs have identical bytes, modes and Git blobs across the
native and merged revisions (`continuity.json`). The native measurements stay
at their recorded source revision; this is not a merged-tree native rerun.

Reproduce these checks independently of the performance reservation:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$PWD/ignored/NEW_NATIVE_GATES" --checks-only
```

Independent reviews cover source, comparison predicates, ownership and the
projection code. Actual execution outcomes, log grouping and numerical exports
are root-attested. Review corrected zero-CPU JSON representation and added an
exact saved-trial cardinality check before export; every raw pair remains
required, and an unresolved CPU comparison cannot earn an estimate.
