# Optional backoff qualification

The existing [backoff SDK and wrapper](../backoff-work/README.md#optional-pre-context-sampling)
provide the explicit `--optional` mode. It requires the old 30 stages plus one
fresh exact ignored release test before two independent 520-epoch trials.
There is no result merely from adding this recipe.

To run just the complete prerequisites and deterministic native control:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$REVISION" --raw "$REPO/ignored/optional-backoff-control" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend --optional-backoff-control
```

The additional control runs the exact test
`frontend_native::backoff::optional::tests::native::optional_backoff_native_disable_rearm_and_old_owner`
in the authenticated release libtest artifact with `--exact --ignored
--nocapture --test-threads=1`. It retains 10 CPU seconds, 15 wall seconds,
1 MiB output/file limit and the existing 40-second parent. All prior stages,
comparators, source/tool/artifact guards and strict child cleanup remain.

It requires 13 original and 13 installed calls: one Fast and 12 sampled Slow
returns, 13 packets, 24 events, five history actions/chunks, three epochs and
12 Report records. Its controller-held Fast bracket and live old B owner
across C rearm are checks of real driver operations. This is separate from
clock-loop trials and existing frontend full-state pairs.

`check_output.py` accepts only the exact complete one-test libtest protocol,
empty stderr and literal native terminal. Its separate optional trial parser
checks sparse counts, actual Disabled actions, full 520-epoch completion,
absolute clock bounds, requested worker transport, exports and synced bytes.
It rejects stopped prefixes and never upgrades aggregate trial coverage from
`not-qualified`. The deterministic control checks complete journals and Reports;
the timed trials check journal contents and Report counts. Debug exports are
retained privately and only their hash and size enter public metadata.

The compact result and one-row control CSV remain under ignored RAW. The
wrapper writes two optional trial rows and a public-safe receipt with exact
revision, commands, hardware, source/tool/artifact hashes and the separate
control result. Cache use is recorded, not called a rebuild. No prior failure,
full-state scope, performance or unsupported native behavior is reclassified.

Synthetic controls are independent fabricated transcripts, not native evidence:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/optional-backoff-work/test_recipe.py
```

The new checker and test entry point refuse optimized Python before work.
Existing mandatory controls remain in `backoff-work/test_recipe.py` unchanged.


To select the distinct bounded sink-wait qualification, add
`--sink-backpressure` to the backoff wrapper together with `--optional`;
`--worker-backpressure` remains independent. For example:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/backoff-work/verify.py \
  --revision "$REVISION" --raw "$REPO/ignored/optional-both-wait" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --optional --worker-backpressure --sink-backpressure
```

The two new CLI routes use the same complete population and original deadlines.
`parse_sink_terminal` authenticates the exact sink-policy/window/quantum suffix
before applying every old optional-terminal predicate. The old parser refuses
that suffix, and the new parser refuses an unmarked line. Four additional pure
controls cover mode confusion, malformed/duplicate markers, unchanged numeric
bounds and rejection of the sink flag without optional mode before output
creation. Existing controls and the 13-call prerequisite remain unchanged.

No waiting policy is a native qualification by its existence. Local Full or
hard-deadline failure stops the campaign; later cases remain UNRUN. Sink-wait
results keep their own markers and the earlier failed-campaign link.
