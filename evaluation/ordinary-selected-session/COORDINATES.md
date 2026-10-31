# Complete leaf coordinate interface

`accuracy_functional_owner.py` adds `coordinate-prepare` and
`coordinate-functional`. Existing fixed profiles and receipts retain their
original options. This interface performs one attempt for one coordinate; it
does not schedule a sweep or award an accuracy result.

The canonical command order is the existing common owner arguments:

```
python3 -B evaluation/ordinary-selected-session/accuracy_functional_owner.py
  --phase coordinate-prepare
  --revision REVISION --reservation-tag TAG --owner ABS_OWNER --raw ABS_RAW
  --toolchain ABS_TOOLCHAIN --user-home ABS_HOME --cargo-home ABS_CARGO_HOME
  --hardware HARDWARE
  --build ABS_BUILD --build-sha BUILD_SHA
  --build-owner ABS_BUILD_OWNER --build-owner-sha BUILD_OWNER_SHA
  --controls ABS_CONTROLS --controls-sha CONTROLS_SHA
  --controls-owner ABS_CONTROLS_OWNER --controls-owner-sha CONTROLS_OWNER_SHA
  --master MASTER --population-phase comparison --trial 100 --workload long
  --k 1000 --period-ms 1 --epoch-phase random
```

The lines above describe one argv, not separate shell commands. All paths are
absolute. The existing external three-CPU reservation, release build and
closed control receipts remain required. Preparation additionally executes
the exact 16 names in `accuracy_coordinates.CONTROLS` through the existing
20 CPU-second / 30-second bounded helper. Consumption rechecks that census.

For `coordinate-functional`, use fresh owner/raw destinations and insert
these arguments after `--controls-owner-sha`, before `--master`:

```
--preparation ABS_PREPARATION --preparation-sha PREPARATION_SHA
--preparation-owner ABS_PREPARATION_OWNER --preparation-owner-sha PREPARATION_OWNER_SHA
--geometry ABS_GEOMETRY --geometry-sha GEOMETRY_SHA
```

The coordinate must match preparation exactly. Geometry uses kind
`selected-accuracy-coordinate-functional-geometry-acceptance-v1`, scope
`selected-accuracy-coordinate-functional-v1`, and the existing nine independent
unsafe-premise acknowledgements bound to the complete current-cell facts and
preparation hash. An earlier fixed-coordinate acceptance cannot substitute.

Master is 64 lowercase hex digits. The supported domain is all three population
phases, trials 1–100, six workloads, K={1,10,100,1000}, periods={1,10,100} ms and
requested epoch phases={random,locked}: exactly 43,200 coordinates per master.
All 2,048 canonical input records and all four material files are recomputed.
Random delay comes from the manifest, never a free CLI value. E520 is fixed.

The existing prepared Rust command/reader retain target epoch j=1, target
`period + original delay`, actual ARM2/history joins, the shared-clock
observations and the original 2 ms ARM gate. Phase realization remains
UNRESOLVED, including whole-period lateness. At 1 ms the original end is
520 ms; at 100 ms it is 52 s, but the producer's original absolute 15-second
exchange deadline still applies. The 20 CPU-second / 30-second helper,
1,200-second outer owner, 8 MiB streams, 350-byte lines, 13,873 success rows and
13,874 failure-envelope rows are unchanged. The new route derives only its
input/write ceiling from the exact population: 4,096–133,120 bytes. Old routes
retain their 68,608-byte/write check. Incomplete input, cancellation, deadline
miss and partial populations remain failures with raw outcomes retained.

## Catalog without a runner

`accuracy_coordinates.py --master MASTER --output FRESH_JSON` writes the
complete keyset definition/hash with all 43,200 cells UNRUN. It stores axes and
the SHA256 of every canonical key in fixed order, rather than thousands of
duplicate empty rows. `--dispatches ABS_JSON --revision REVISION` projects a complete retained
dispatch list. Before importing project validators, it authenticates its finite
source closure against that exact Git revision; every closed report must use
the same revision. Each element has exactly `coordinate`, integer `attempt: 1`,
`owner` and `result`; coordinate keys use the CLI spellings above, with integer
trial/K/period. Owner/result are either null or `{path,bytes,sha256}` pins.
Record the dispatch before launch, retain that record and all closed outcomes,
and supply every dispatch on each projection. Never replace a failed attempt
with a later run. Duplicate coordinates/attempts refuse. A missing catalog
coordinate is UNRUN; a dispatched coordinate without proven closed custody is
UNKNOWN. The collector reads owner first and checks existing closure, command,
source-receipt, log, coordinate and full-population joins before projecting a
reported structural outcome. The new profile's owner-owned summary binds the
coordinate, all policy/material facts and the used joined identity; the
collector independently recomputes the manifest policy and exact scalar joins.
Old profile summaries stay unchanged. It never launches or retries a process.

The dispatch input is canonical compact JSON plus LF, with at most 2,048 bytes
per canonical event. Its separate aggregate read bound is derived from all
43,200 events; this does not alter any application stream or owner bound.

All output paths are create-only. Keep dispatch/receipt/raw files private.
Catalog completion means only all structural reports closed; it is not an
independent replay of every raw stream and does not grant phase, hardware,
performance, executed-trace or full-A5 accuracy. Failure/UNKNOWN/UNRUN counts
remain explicit. Existing strict-clock and finite-profile failures remain
separate historical evidence, not superseded by this interface.
