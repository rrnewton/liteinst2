# Original-address nested-call qualification

Revision `53dbeb765aaa23be6ab19e76a4fd6d950311e81c` adds the native oracle
for an actual admitted Rust caller, its original parent CALL, and the parent's
original E8 CALL to a child. It compares architectural state and the enclosing
stack through both target returns and the outer caller return.

The one fixed release qualification **FAILED** on the first candidate at the
unchanged 20,000-step limit. It completed **zero of 192 pairs** and produced no
pair rows. There was no retry. No native-state, application-timing, performance,
or full-A5 qualification follows from this run.

All 36 prerequisite stages closed normally: 208 Rust calibrations plus one
unchanged ignore, 14 ordinary controls, 29 SDK controls, eight core controls,
and 96 Python controls. Emitted caller/parent/child geometry was accepted.
The final native stage exited 101 after 3.271 seconds; its outer owner exited
1 after 197.973 seconds. Both closed with complete cleanup and zero rescue
reaps. These durations are validation costs, not performance measurements.

After closure, the summary collector authenticated 321 retained files
(58,795,437 bytes) and all 1,171 source pins. Raw logs and captures remain
ignored. `receipt.json` records exact revision, tool/protocol/receipt hashes,
command and environment with named local-path placeholders. `stages.csv`
retains every stage outcome, including the failure.

Hardware: AMD EPYC Zen 5 dev host. Rust 1.97.1; release optimization 3,
assertions and overflow checks enabled, incremental compilation disabled,
four compiler jobs. The hard reservation was CPUs 16/138/146; tracer and
tracees used 138. Load moved from 38.43/31.95/34.50 to 35.56/35.95/35.85.
Reservation evidence is the authenticated normal allocator return; no
independent ledger readback is claimed.

Reproduce from the exact clean revision with the
[tracked recipe](../ordinary-call-pair-native/README.md), inside a fresh hard
three-CPU reservation and a 1,200-second, 8 MiB external process owner:

```sh
python3 -B evaluation/ordinary-call-pair-native/reproduce.py \
  --revision "$REV" --reservation-tag "$TAG" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --raw "$REPO/ignored/NEW_CALL_PAIR_NATIVE_RUN"
```

Keep the complete 192-pair cohort and existing 480 CPU/510 wall seconds per
cohort, 15 seconds per pair, and 20,000 steps per child. The 2 ms arm, 10 ms
cadence and 2 s shutdown application gates remain unchanged and are outside
this native run's scope. Claim 4 is supported only by the completed controls;
the original-address nested native prerequisite remains open.
