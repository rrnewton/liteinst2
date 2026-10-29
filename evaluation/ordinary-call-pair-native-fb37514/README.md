# Shared acknowledgement preflight: fixed native qualification

Revision `fb3751426891c689dca49ef02319ef8d8a9528ce` reuses acknowledgement's
completed validation while preserving standalone completion, transfer and all
receipt-consumption checks. Existing controls gain 572 acknowledgement
corruption cases and pending-receipt rearm/drain checks.

The single fixed release qualification **FAILED**, with **zero of 192 pairs
accepted** and no retry. The first candidate reached postflight after the
stepped calls and returns. Its final-history check expected `[false]` for the
group-policy bits and observed `[true]`; the parent then rejected the child's
nonzero exit. No complete pair row was emitted. The preceding
[step-limit failure](../ordinary-call-pair-native-15b3de6/README.md) remains
recorded separately. No native qualification or performance claim follows.

All 36 prerequisites passed: 208 calibrations plus one unchanged ignore,
14 ordinary controls, 30 SDK controls, eight core controls and 96 Python
controls. The native stage exited 101 after 3.356 seconds; its owner exited 1
after 184.889 seconds. Both closed with complete cleanup and zero rescue
reaps. All 321 retained files (58,809,615 bytes) and 1,171 source pins were
authenticated after closure. Durations are operational validation costs.

Hardware: AMD EPYC Zen 5 dev host; Rust 1.97.1, release optimization 3,
assertions and overflow checks enabled, four compiler jobs, no incremental
compilation. Hard reservation: CPUs 64/208/215, with tracer and tracees on 208.
Load moved from 61.51/68.10/58.15 to 57.55/62.58/57.83. Reservation evidence
uses normal allocator return; no separate ledger readback is claimed.

Reproduce with the [tracked recipe](../ordinary-call-pair-native/README.md)
from this exact clean revision in a fresh hard three-CPU reservation and the
same 1,200-second/8 MiB external owner:

```sh
python3 -B evaluation/ordinary-call-pair-native/reproduce.py \
  --revision "$REV" --reservation-tag "$TAG" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --raw "$REPO/ignored/NEW_CALL_PAIR_NATIVE_RUN"
```

`receipt.json` records the exact command/environment using local-path
placeholders, source/tool/artifact/closure hashes, reservation and limits.
`stages.csv` retains all 37 outcomes. Raw logs and captures remain ignored.
Claim 4 support is limited to the completed controls. The native prerequisite
and full A5 remain open; the 20,000-step and 15-second per-pair limits, and the
strict 2 ms/10 ms/2 s application gates, remain unchanged.
