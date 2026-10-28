# Exact-work CALL enclosures

`ordinary-interval exact-reference CANDIDATE TRUSTED` is an additive, finite mode for the independently pinned exact-work assembly DSO. Candidate and trusted expected ELF must be distinct files; the loader compares the complete candidate against the trusted bytes. The existing `exact-work` schedules and all twelve trials are unchanged.

One actual main thread is pinned to one CPU. Before any call it fixes 24 IDs (`0x72656600 + i`), alternating lengths 1/64, immutable guarded input and expected scalar results. It invokes all 24 originals with the reference-profile library gate, publishes the complete entry/every-RET bundle while still sole-threaded, attaches once, arms K24 and invokes all 24 installed calls on that same thread. It detaches, disarms and validates the complete Report before success/output. No worker is spawned and no thread-join observation is fabricated. Input reclamation follows all physical returns and detachment; executable/source ownership remains process-lived.

The unchanged exact-work joiner authenticates each installed ID's one new raw row, complete prior prefix, ordinal, generation/invocation, value/RSP, totals and full Report records/payloads. The wrapper separately authenticates SDK leg, gate/PID/TID/target/continuation, exact external ID and RSP against the actual result. The first real original gate sequence establishes the lifetime baseline, allowing earlier calibration/original calls. All 48 gate sequences must be consecutive; installed raw ordinals remain 1..24. All reference and raw AUX values must equal the first qualified reference AUX. Calls must be chronologically ordered, and each installed row must satisfy `ref.start <= raw.start <= raw.end <= ref.end` with checked `entry_gap + raw_ticks + return_gap == enclosure_ticks`.

CSV contains 24 original rows followed by 24 installed rows. Original rows leave raw-row/owner-generation/invocation/endpoints/gap fields empty; they never invent callbacks. Installed rows contain both endpoint pairs, raw/enclosure ticks and the two declared boundary gaps. Each leg's exact source-work population is 4,800 instructions, 780 conditional branches, 756 taken branches, 780 input-byte reads and 192 RET-read bytes. These counts come from the independently specified assembly/interpreter and are not timing truth or a new native trace.

The terminal is `exact-reference FUNCTIONAL_PASS ... uncalibrated=true`. These are uncalibrated elapsed TSC enclosures including gate instructions and descheduling, not original leaf duration, on-CPU cycles, nanoseconds, accuracy, constant-overhead subtraction or a performance result. The same physical clock supplies the independently placed readers; AUX equality alone does not prove absence of migration. The reference SDK's explicit hardware/stable-platform contract and singleton affinity remain mandatory. Original-before-installed order is not a drift experiment.

The separate full-state reference-gate native qualification must pass before this untraced mode is run. It retains the old comparator and expands the new-profile stack extent; this CLI does not replace it. No U/Rmin heuristic, calibration formula, outlier trimming, accuracy budget or full-A5 claim is implemented.

Run the bounded release recipe from the repository at the revision being measured:

```sh
python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision "$REVISION" --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --exact-work --concurrent-epochs --retire-epochs --drain-completed \
  --streamed-epochs --stream-history --optional-frontend \
  --optional-backoff-control --reference-timing
```

`REVISION` is the exact clean source commit. `RAW` must be a new absolute directory under the checkout's ignored directory; the other arguments name the actual local toolchain and user/Cargo directories. The recipe builds with release optimization level 3, debug assertions and overflow checks. All 31 previous stages remain required. It then builds and runs the full native validator control target, executes four reference state pairs, and runs the untraced client only after those checks succeed. Each pair shares an absolute 15-second deadline, and each child keeps its 20,000-step bound; the parent state command has a 90-second bound. Raw logs and artifacts stay ignored; `reference-rows.csv` and `reference-state-pairs.csv` are the compact numerical outputs. The recipe requires the AMD reference-clock profile and records observed hardware, tool versions, binary identities and the exact source revision.
