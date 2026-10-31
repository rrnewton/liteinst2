`output.py` consumes the complete `selected-accuracy-session-v1` wire. It does
not launch a producer or select trials. Its pure controls use fabricated streams:

```
python3 -B evaluation/ordinary-accuracy/reader_controls.py
```

The caller authenticates the reader, shared leaf-set checker and `truth.py`
before loading them, then calls:

```
check(stdout, stderr, *, manifest_bytes, input_bytes, selected_bytes, truth_bytes,
      table, caller, body_bytes, abi, policy, cpus)
```

All four original materials must exactly equal `truth.py`'s complete independent
2,048-record population. `table`, `caller`, `body_bytes`, `abi` and `cpus` must
come from separate admission of the actual immutable ELF files, code, caller,
platform and unsafe invocation contract. The table is exactly one whole-function
entry: ID 41, `exact_work_nonempty`, extent 37 and RET offset 36. The ABI marker is
`sysv-amd64-u64-pointer-length-v1`. Equality with the literal body is only one
check; it does not establish whole-ELF identity, actual mapping ownership, an
ordinary caller, physical returns or lifetime safety.

`policy` has exactly `k`, `period_ms`, `epochs`, `phase` and `delay_ns`. Its K,
period and requested phase/delay must match an enumerated manifest policy, and
the wire must have the same K, period and epoch limit. `manifest.phase` names the
independent calibration/holdout/comparison population. `policy.phase` requests
random/locked input timing. These meanings remain separate; matching the input
manifest never proves actual timing. Every ARM observation must immediately
follow its actual publication, use its original due time and finish within the
unchanged inclusive 2 ms deadline. These are checks of recorded values; the
process owner must separately establish their custody and actual closure.

Successful decoding returns `STRUCTURALLY_COMPLETE`, with every observed wire
row, complete input truth, CALL/RESULT, sampled or unsampled identity, both raw
counter endpoints per call, all four attribute chunks, ID/enable, ARM and
disable/close records. Nothing is reconstructed as an observed field. Counter
words and checked unscaled differences are separate from their limitations:
errors, short reads, missing/mismatched IDs, changed attributes, owner drift,
AUX changes, clock regressions, zero running and multiplexing remain visible.
`full_running` describes raw time differences only, not trustworthy hardware
counts. Disable/close failures remain in `session_limitations` and the raw close
records. Both `hardware_status` and `requested_phase_status` stay `UNRESOLVED`.
There is no scaled count, body-only attribution, perf attribution or accuracy
verdict. Callback windows also include observer work and stop before the physical
RET, so their raw counters are not the original leaf's complete-work counts.

Invalid/incomplete framing, structural drift, a failed ARM deadline or terminal
stderr raises `Refused`. Its `raw` and `stderr` retain the exact original bytes;
this is not a complete record set or a converted success. Bounds are 8 MiB,
350 bytes per line and `5*2048 + 3*epochs + 20` lines. The old public readers
retain their old vocabularies, profiles, caps and refusal checks; they reject
this new wire. Actual process exit, cleanup, source/tool/file custody, complete
journals, hardware calibration and native architectural state remain external.


The opt-in `phase_output.py` reader admits only `selected-accuracy-phase-session-v1`.
The old `output.check` remains strict for `selected-accuracy-session-v1`; neither
public wrapper selects a profile from observed output. Both use the unchanged
numeric/history/PMU predicates through a closed two-profile internal seam.

The new wire places `PHASE,random|locked,delay_ns` after the one `RET` row. Every
existing `CALL`/`RESULT`/two-`PMU` group is followed by
`CALLTIME,ordinal,record_id,41,before_invoke_ns,after_return_ns`. Only the first
such group also has `RELEASE,1,41,gate_enter_ns,released_ns` immediately before
its `CALLTIME`. The reader requires every one of the 2,048 IDs, in order, one
release, the exact manifest policy/delay, the accepted first ARM before the
gate, monotone enclosures and the original epoch-end plus two-second safety
fence. An already-due gate must report identical gate/release offsets. No row,
header, ID, endpoint, ARM outcome or failed byte is repaired.

These offsets share the application's Schedule `Instant` origin. They are not
comparable with TSC, PMU clocks or the producer's `monotonic_ns` observations.
`csv::invoke` enclosures include the ordinary CALL/store/RET wrapper; they are
not exact leaf entry or return instants. The decoder retains absolute release
lateness, epoch index/remainder, all per-call requested-offset error
enclosures, enclosed original due numbers and ARM interval overlap counts. NORMAL/history still owns the sampled generation. Neither a
modulo match nor a non-overlapping enclosure establishes phase realization.
The requested phase and metric/calibration statuses remain `UNRESOLVED` until
a separate prospective numerical calibration and phase criterion exists. ARM
lateness remains the original inclusive 2 ms gate, not a phase tolerance.

For one leaf, the bound is `6R + 3E + 22`: at R=2,048 and E=520 there are at most
13,870 lines, each at most 350 bytes (4,854,500 bytes), within the unchanged
8 MiB accepted-stream cap. Missing/partial/overflow/error output is refused
with its original consumed bytes retained. Source controls, not execution
results: `python3 -B evaluation/ordinary-accuracy/phase_controls.py -v`.
