# Whole-invocation raw counter probe

`ordinary-interval counter-cache-probe CANDIDATE TRUSTED NEW_OUTPUT_DIRECTORY`
observes twelve original calls to the unchanged loaded linked-memory leaf: the
six cache-work cases under each existing seed. Each call has a fresh current-thread
Linux perf event, raw config `0x0964`, disabled and pinned, no inheritance, user
only (kernel/hypervisor/guest excluded). It reads value/enabled/running/ID while
disabled, enables, calls the full original API once, disables, reads, and closes.
No reset, scaling, syscall retry, replacement population or repeat-until-pass is
used. Counter failures preserve exact return values/errno and partial read bytes.
The first failure stops the population; remaining IDs are explicitly `UNRUN`.
`invoked` counts API closure attempts. A returned API error can precede the
subject CALL; only successful rows attest the gate's actual normal return.

The enabled window includes Rust dispatch, both original-owner checks and
postflight. Kernel exclusion does not remove kernel-induced cache perturbations.
These are whole-API observations, not an instruction-positioned body interval.
`OBSERVED_FULL_RUNNING` requires positive enabled==running deltas, matching
event identity, monotonic raw words, unchanged observed singleton CPU identity,
successful cleanup and the actual expected scalar/return/input checks. It does
not establish event sensitivity, timing accuracy or equality with a cache model.
A zero count with positive full running time remains a raw zero.

Linux v6.18's [mapfile](https://github.com/torvalds/linux/blob/v6.18/tools/perf/pmu-events/arch/x86/mapfile.csv)
maps AMD family 26 to the [Zen 5 event table](https://github.com/torvalds/linux/blob/v6.18/tools/perf/pmu-events/arch/x86/amdzen5/l2-cache.json).
That table defines event `0x64`, mask `0x09` as instruction/data core-to-L2 request
misses, excluding L2 prefetch. AMD publication 58550 revision 0.02, page 31
([public attachment](https://bugzilla.kernel.org/attachment.cgi?id=305974)) defines
the same bits; page 6 adds other events when computing *all* L2 misses. It covers
models 00h–0Fh, while the development host reports model 11h. Exact model-11h
semantics and errata remain unqualified. The event is neither data-only misses
nor the software model's 512-byte cache, and excludes no other prefetch class by
this claim.

The existing release reproducer adds this capability with `--counter-probe`,
which requires `--cache-work --exact-work`. Retain the other previously used
flags when reproducing the full accumulated qualification. Its prerequisite
cache stage still requires all twelve original/installed full-state pairs and
all 58 validator controls. The counter stage adds twelve untraced original calls;
it makes no new instrumented/full-state or hardware-accuracy claim. A nonzero
probe exit remains a failed required stage even when its refusal CSV parses.

```sh
python3 -B tools/rapid-profiler/counter-work/test_recipe.py
cargo test --locked --offline --release -p rapid-profiler --lib counter_probe::tests
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$(git rev-parse HEAD)" --raw "$PWD/ignored/counter-probe-run" \
  --toolchain "$TOOLCHAIN" --user-home "$HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --cache-work --counter-probe
```

The output keeps three compact CSVs: the complete population, raw endpoints and
attributes, and every syscall result. Receipts retain the exact source revision,
commands, hardware and bounded-process closure. Raw logs stay under `ignored/`;
publish only the compact receipt and numerical CSVs under `evaluation/`.
