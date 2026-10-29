# Compact journal validator: fixed native qualification

Revision `15b3de612e3d8466cdb3e4f77c0ff9d61d2c300a` retains all 512
ordered journal reads while avoiding full-page temporary arrays. It also adds
failure-only parent-side step attribution. All prior checks and bounds remain.

The single fixed release qualification **FAILED** on the first candidate at
20,000 steps. It completed **zero of 192 pairs**, with no pair rows and no
retry. The preceding [qualification](../ordinary-call-pair-native-53dbeb7/README.md)
also remains failed. There is no native qualification or performance claim.

The new diagnostic accounts for all 20,000 completed single-step requests:

| Phase | Requests |
| --- | ---: |
| Reach caller | 34 |
| Caller before parent CALL | 6 |
| Parent entry through child CALL | 3,142 |
| Child entry through physical child RET | 6,804 |
| Child landing through acknowledgement | 7,346 |
| Parent continuation and return phase, incomplete | 2,668 |
| Parent landing and outer RET | 0 |

The stopped PC joins the retained executable's file-backed executable segment
and `call_pair::runtime::journal_matches_prefix`, offset 504. These are tracer
step requests, not retired-instruction or throughput measurements. The child
acknowledgement includes two complete preflights in this revision; the data
identifies where further implementation work is needed, not permission to
relax a limit.

All 36 prerequisites passed: 208 calibrations plus one unchanged ignore,
14 ordinary controls, 30 SDK controls, eight core controls and 96 Python
controls. This includes the added 3,584 journal corruption cases. The native
stage exited 101 after 3.807 seconds; its owner exited 1 after 179.353 seconds.
Both closed with complete cleanup and zero rescue reaps. All 321 retained
files (58,769,349 bytes) and 1,171 source pins were authenticated after closure.
Durations are operational validation costs.

Hardware: AMD EPYC Zen 5 dev host; Rust 1.97.1, release optimization 3,
assertions and overflow checks enabled, four compiler jobs, no incremental
compilation. Hard reservation: CPUs 37/154/176, with tracer and tracees on 154.
Load moved from 39.05/48.85/47.66 to 44.97/45.37/46.40. Reservation evidence
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
Claim 4 support is limited to the completed controls. The original-address
nested native prerequisite and full A5 remain open; the strict 2 ms/10 ms/2 s
application gates are unchanged and were not exercised here.
