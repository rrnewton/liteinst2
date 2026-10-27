The 22-stage release recipe passed at
`84d004098e57245528de5d11657892fffd0cb010`. After a separately documented
creation-identity cleanup fix, all seven required checks passed at
`088dc0a3662a4661328604db6e96f28c7cd80775`: workspace 2,546 passed / 0 failed /
5 ignored. The [follow-up report](../creation-identity-088dc0a/README.md) retains
both failed gate attempts and the separate unresolved backing-child panic.

| Check | Closed result |
|---|---|
| Existing checksum state oracle | 4 pairs / 8 children / 978 comparisons |
| Existing exact-work state oracle | 4 pairs / 8 children / 844 comparisons |
| Concurrent-activation state oracle | 4 pairs / 8 children / 844 comparisons |
| Forced native contention | 6 originals + 6 installed; 4 sampled, 1 closed, 1 removed; 2 writer waits; 1 in-flight rearm |
| Timed epochs | 24 originals + 24 installed; 18 sampled / 6 removed; 3 epochs / 6 transitions; coverage `[6,2,6,2,6,2]` |

The unchanged state comparator covers gate entry through post-POP, then real
outer return after harness restoration (exact scope in receipt). Concurrent
activation runs it **without a competing controller**. The separate forced test
checks gate/stack/input/journal/report ownership, with no full contended-register
state credit. Registry waits were zero.

The timed worker/controller used distinct CPUs and one startup rendezvous, with
no application mutex or per-call acknowledgements. Preassigned IDs and actual
brackets join intervals/reports; every settled active/inactive window had calls.
The requested 30/10 ms windows are scheduling inputs; mandatory hooks stay active.
Existing checksum calls (8; reports 4+2) and 12 exact populations (288 calls;
140 sampled / 148 closed) also passed; their old rows are not duplicated.

This is bounded functional evidence, not calibrated timing, performance, whole
stack, indefinite service, or full A5. Rust release opt3 retained assertions and
overflow checks. The receipt binds tool/profile/artifact hashes and observed CPU
fields; “AMD EPYC Zen 5 dev host” is owner-supplied. Command seconds are operational.

The gate attempt passed fmt/Clippy/check, then workspace exited 101 at
`raw_newborn_failure_retains_unjoined_native_identity_and_actual_prefix`
(`dynamic physical cleanup ownership was lost`). Its library terminal 741/1 is
not a complete workspace count. Cleanup completed with zero rescues; serial,
staged-allocation and prefixed-pun checks were UNRUN. This failure remains
recorded under its original revision. The follow-up source changes are confined
to liteinst-launch and its evaluator; rapid-profiler's dependency closure is
unchanged. Later validation does not relabel this first attempt as a pass.

From a clean checkout at the tested revision with matching tools/dependencies:

```sh
env -u PYTHONOPTIMIZE python3 -B tools/rapid-profiler/verify_ordinary_interval.py \
  --revision 84d004098e57245528de5d11657892fffd0cb010 --exact-work --concurrent-epochs \
  --raw "$REPO/ignored/NEW_NATIVE" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```

Variables denote checkout, Rust toolchain and configuration/cache directories;
outputs must be fresh. Tested: Python 3.12.15, Rust 1.97.1. `commands.csv` preserves
stage argv/bounds; `$RAW` is output, `$RAPID_LIBTEST` the selected release artifact.

`python3 -B project.py --native "$SAVED_NATIVE" --gates "$SAVED_FAILED_GATES"
--out "$NEW_PROJECTION"` regenerates receipt/CSVs from exact closed metadata.
README/projector are authored. Four numeric CSVs are byte-exact; timed calls
retain 24 IDs/outcomes/raw times, replacing pointers with checked offsets.
Report `thread` is logical. The projector reads no binaries/captures/raw streams.
