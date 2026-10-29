# Four-mode segmented elapsed observations

This additive recipe compares five fixed blocks of native, always-on, back-off K10 and back-off K1000 configurations. Every member performs the same 3,072 calls, 1,536 helper returns and 614,400 specified original instructions. The 20-slot order is fixed before qualification: N/A/K10/K1000, A/K10/K1000/N, K10/K1000/N/A, K1000/N/A/K10, then N/A/K10/K1000. There are no warmups, retries, tuning or outlier removal.

From a clean reviewed commit, under an externally owned four-CPU reservation with hard AllowedCPUs, run:

```sh
python3 -B tools/rapid-profiler/normal-work/backoff_elapsed_probe.py \
  --revision "$REVISION" --reservation-tag "$RESERVATION_TAG" \
  --raw "$REPO/ignored/NEW_RUN" --toolchain "$RUST_TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

The directory arguments must be absolute; raw output must be fresh. The sorted reserved roles are producer CPU0, application CPU1, timer CPU2 and back-off controller CPU3. Affinity, a tag and load observations do not prove reservation or quiet hardware; the outer owner must join the actual allocator and containment evidence. Child bounds remain 20 CPU seconds, 30 wall seconds and 1 MiB; bounded helpers retain 55 seconds/1 MiB and the required outer owner 1,200 seconds/8 MiB.

The driver requires the unchanged fresh 34-stage ordinary qualification, the full old throughput/back-off/timer control cohorts and new elapsed controls. Both existing command-driven pending-owner controls must pass before any measured member. It runs no extra untimed back-off catalog. The old back-off runner also requires the seven newly compiled elapsed Rust controls; its broad inventory equality includes all 21 cases.

Each process retains its full functional output and all 130 RAW setup/body/service rows. Body spans bracket twelve actual helper invocations per block, including wrapper work and next-entry confirmation. First preflight precedes service; subsequent preflights, postflight, checkpoints and final validation are inside. Back-off service includes controller shutdown. Validation costs differ by mode, so these are whole validated configuration quantities, not pure observer overhead or application speedup. Setup plus service is not an exhaustive process partition.

The unchanged process timer separately encloses immediately before fork through immediately after wait4 and records child user/system CPU. Its MONOTONIC origin is never compared with absolute collector MONOTONIC_RAW endpoints. Application PID must join the actual transcript to timer child/wait PID and exact argv token. Printed success followed by nonzero native completion remains FAILED. If the actual strict checker refuses the output or stderr, APP identity is unconfirmed and remaining slots stay UNRUN; an empty stderr is never fabricated.

Private output retains all requests, closures, streams, artifacts and per-call tables. The public projection contains every slot, every accepted raw timing row and 15 native-denominator comparisons. Ratios are exact numerator/denominator pairs for body and service only when both members passed all identity and closure checks; zero native denominators remain UNRESOLVED_ZERO. Failed members have no ratios. Any uncertain shared custody withholds all ratios. There is no subtraction, accuracy, confidence, continuous-throughput or full-A5 claim. Prior strict 2 ms/520-arm results retain their original status.
