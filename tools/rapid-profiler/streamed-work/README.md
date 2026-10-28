# Finite streamed epochs

`--streamed-epochs` adds one fresh `ordinary-interval streamed-work` process after
all 25 existing required native stages. It requires `--drain-completed`, which
retains the retirement, concurrent, exact-work and checksum requirements.
The new stage uses the same release artifact and exact-work DSO already built
and authenticated by the recipe: optimization 3, debug information 0, assertions
and overflow checks enabled. Its helper limits are 20 CPU seconds, 30 wall
seconds and 1 MiB output, with the unchanged outer cleanup supervisor.

From a clean committed checkout, with absolute existing toolchain and home paths
and a fresh output directory under `ignored`, run:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$REVISION" --raw "$REPO/ignored/streamed-run" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed --streamed-epochs
```

The fixed trial performs 160 original calls, then 160 installed calls in one
worker registration. It uses 20 epochs, three reusable slots, 17 replacement
stages and 40 explicit four-call drains. Lengths alternate between 1 and 64.
The controller schedules 30 ms active / 10 ms off windows over a nominal
800 ms interval, with a separate 2 second schedule deadline. Replacement stages
must finish strictly before their future arm deadline minus 10 ms. Worker and
controller run on distinct selected CPUs without an application mutex around
calls; a bounded channel transfers complete owned batches.

The Python parser requires all 40 actions, 160 calls, 40 batches, 20 retirements,
all sampled Report projections and the exact success terminal. It independently
checks external IDs, lifetime ordinals, original checksum/length truth, global
completion sequences and raw/event/gate cursors, actual operation/call brackets,
replacement cutoffs and stable whole-call coverage in every active/off window.
Every call and retirement must finish by the observed final window end.
Sampled counts come from actual owner records; 120 sampled / 40 removed is not
a required or substituted observation. A return may retain its original owner
across a controller removal.

The saved five CSVs are private raw projections and include addresses. The
result JSON contains compact numeric summaries and their hashes. Full guarded
input bytes, original invocations, complete 512-word journal pages, batch owner
identity, full Report/terminal payloads, gate returns and retirement permits are
checked by the Rust client; those unexported objects are source-attested, not
independently reconstructed by this parser. Earlier native-state qualification
remains separate. Mandatory entry/RET hooks stay active during off windows.
Raw RDTSCP values are uncalibrated; this trial establishes no timing accuracy,
throughput saving, indefinite service, general-program coverage or completed A5
milestone. Failed or partial output is never accepted as a complete trial.

Pure fabricated-transcript controls can be run separately:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/streamed-work/test_recipe.py
```

These controls provide no native execution credit.
