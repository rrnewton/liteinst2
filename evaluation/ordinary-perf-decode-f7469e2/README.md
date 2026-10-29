# Offline perf decoding and retained refusals

This adds a bounded, independently reviewed `perf.data` reader and 24 fabricated
controls. It does **not** qualify this capture for a profiler accuracy comparison.
Decoder revision: `f7469e2cd600795142e0821f81def129c0cc7dff`. Hardware: AMD EPYC Zen 5
dev host. All current decoder, record, CLI and test bytes match that revision.
The final evidence commit adds this report/reproducer and clarifies documentation;
it changes no decoder or application executable source.

The sole retained capture is 644,256 bytes, SHA-256
`5b46da1edb6017ab187c2c7760054a43ef6bf4628d5d0fd0247f07fa70bf4aef`,
from release source `5fb97c53d5d5fc330bdceecb6cb7bf843b03da49`.
[Its capture receipt](../ordinary-task-retirement-5fb97c5/receipt.json) records
release settings, fixed work, command recipe, CPU reservation and load. No new
capture or timing campaign ran for this report. Raw logs, full command JSON and
capture bytes remain in ignored storage.

| Inspection | Result |
| --- | --- |
| Whole-file framing | All 2,608 records / 242,256 record bytes framed; all file bytes accounted for |
| Exact external command join | REFUSED at byte 253,596: expected 40 argv words, metadata contains only the executable word |
| Separate view without command authority | REFUSED at byte 23,548: sample context outside the host-user profile; 120 records decoded before refusal |
| Complete SAMPLE header inventory | 1,764 frames: 1,637 USER (`misc=2`), 127 KERNEL (`misc=1`) |
| Diagnostic decoded prefix | 12 samples; recorded period sum 49,152; one throttle observation; 90 READ records with value 0, enabled 249,771,741, running 0, lost 0 |

The strict refusal remains unchanged beside the separate diagnostic. Prefix
numbers are **not** whole-capture totals, APP totals or per-function estimates.
The 90 READs are grouped observations, not a sum or final counter. Unequal
READ times do not by themselves establish active-event multiplexing: event,
task and CPU accounting is unfinished. The complete framing inventory also
contains 250 THROTTLE and 249 UNTHROTTLE frames; only the decoded prefix receives
semantic interpretation. An empty adverse list before semantic decoding is not
proof that the capture has no adverse observations.

Kernel-context sample headers do not prove corrupt data or counted kernel
instructions. Pinned [Linux v7.3-rc2 core source](https://github.com/torvalds/linux/blob/v7.3-rc2/kernel/events/core.c#L7802)
explicitly permits user-event interrupt skid after kernel entry. Counting
exclusion and sampled context differ. This is a supported-profile boundary of
the current reader. It still refuses these records; no mode, deadline, tolerance
or qualification check was relaxed. Upstream source does not authenticate the
running kernel or establish any particular sample's cause.

The first decoder draft also refused the regular BUILD_ID header at byte
245,448. Its assumption of synthesized type 67 was wrong: the pinned regular
writer emits type 0 and separately aligns the filename allocation. The corrected
reader adds exact padding/reserved-byte checks and rejects the former fabricated
positive as a negative control. `decode-history.json` retains that initial
refusal, its working-source hashes, both current refusals, and the private
inspector's failed frame-offset lookup before its four-byte correction. The
original outcomes and capture were not replaced.

The reproducible current source is committed. The earlier draft is represented
by its exact working-source hashes and historical receipt; it is not presented
as a second committed decoder revision. `observations.json` is the lossless
numeric summary emitted by the current reproducer. `checks.csv` includes every
listed development/control/inspection outcome and the seven workspace checks.
These records support claim 4's validation machinery, not an accuracy advantage.

## Reproduce

Authenticate the checkout and decoder sources listed in `receipt.json` first.
Supply the retained capture and independently retained command JSON; do not
construct expected argv by copying metadata from the capture. The latter JSON
hash is `067de69478dbdd0ed7d4ce5eed23bd9f16461adfc0bd96902983cb2307ef0eaa`.
`CAPTURE` and `COMMAND_JSON` below are local paths, deliberately absent from
public evidence. The command requires those exact bytes, including original
private argv spelling. It never launches perf or an application.

```sh
python3 -B evaluation/ordinary-perf-decode-f7469e2/reproduce.py \
  --data "$CAPTURE" \
  --sha256 5b46da1edb6017ab187c2c7760054a43ef6bf4628d5d0fd0247f07fa70bf4aef \
  --command-json "$COMMAND_JSON" \
  --command-sha256 067de69478dbdd0ed7d4ce5eed23bd9f16461adfc0bd96902983cb2307ef0eaa
```

Exit 0 means the report was emitted. Both nested inspection statuses remain
REFUSED. The outer owner used a 1,200-second / 8-MiB output limit; normal closure
took 0.102 seconds with zero rescues. This duration describes validation cost.
The CLI and reader enforce their own input/record/output bounds, documented in
[PERF_DATA.md](../../tools/rapid-profiler/tree-work/PERF_DATA.md).

Run the 18 decoder and six CLI controls using the two commands in that document.
They passed in 1.144 and 1.433 seconds of outer-owner time. Exact-source rebinding
checks their executed working bytes against the committed source. All seven
workspace checks at the decoder revision passed in 495.984 seconds: default
workspace 3,093 passed / 0 failed / 36 ignored plus two custom harnesses; serial
launch 1,039; staged allocation 3; prefixed pun 36; fmt, strict all-feature
Clippy and all-target/all-feature cargo check. Workspace alone took 330.938
seconds. All eight historical exec-map/allocation regressions passed once under
default parallelism. The check runner is
`evaluation/admission/check_exec_identity.py --checks-only`; its exact seven
commands and authenticated closure hashes are retained in `receipt.json` and
`checks.csv`. Python 3.12.15, Rust 1.97.1, four Cargo jobs, incremental disabled.

APP/mapping identity, terminal accounting, raw PMU event meaning, complete-file
period mass and accuracy remain unresolved. In particular, retained ELF hashes
lack a historical candidate device/inode witness. No throughput, overhead,
per-call perf measurement or full-A5 completion claim follows. The earlier
fixed-five strict 2-ms campaign remains FAILED, PASS, PASS, FAILED, PASS; it was
not retried.
