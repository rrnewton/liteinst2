# Complete context decoding, with all weights unattributed

Revision `1c3e7ed337e74dab01d30c3da7a0152e99fd8872` adds a separate
host-context diagnostic to the bounded perf reader. It preserves the strict
API, CLI, all 24 existing controls and their refusal behavior. Six additive
controls cover context partitioning, malformed payloads, partial results and
bounds. All 30 controls passed. Hardware: AMD EPYC Zen 5 dev host.

The same retained 644,256-byte capture now has complete semantic decoding under
this separate diagnostic profile. No new capture or timing campaign ran.
The [previous strict refusal report](../ordinary-perf-decode-f7469e2/README.md)
and [release capture receipt](../ordinary-task-retirement-5fb97c5/receipt.json)
remain unchanged. Capture SHA-256:
`5b46da1edb6017ab187c2c7760054a43ef6bf4628d5d0fd0247f07fa70bf4aef`.

| Observation | Result |
| --- | --- |
| Exact external command check | REFUSED at byte 253,596; 40 expected words, 1 recorded word |
| Separate context diagnostic | CONTEXT_DIAGNOSTIC_UNQUALIFIED; all 2,608 records decoded |
| SAMPLE records | 1,764; all recorded period weights retained exactly once |
| Host-user sample context | 1,637 records; period sum 6,705,152 |
| Host-kernel sample context | 127 records; period sum 520,192 |
| Complete-file sample period sum | 7,225,344, entirely UNATTRIBUTED |
| Standalone READ observations | 316; 314 have value/running 0, two have nonzero values |
| Throttle / unthrottle records | 250 / 249 |

The complete-file number is a sum of recorded SAMPLE period fields. It is not
a terminal counter, APP instruction total, function cost or per-call estimate.
Sampled context does not establish counted privilege. The diagnostic never
assigns kernel-context samples to a user function. Unknown contexts and malformed
payloads still refuse. A partial result retains its decoded prefix and sets its
complete-file period total to null.

The READ groups retain value, enabled, running and lost without scaling or
addition. The two nonzero tuples have values 37,656 and 7,366,925, with running
times 1,153,352 and 248,618,389; all 316 have enabled 249,771,741 and lost 0.
These are descriptive observations, not selected final counters. Unequal
per-event times alone do not establish active-event multiplexing. Event, task,
CPU and lifetime joins remain necessary. Throttle and loss completeness remain
separate qualification questions.

The command mismatch remains in the report verbatim. Upstream v7.3-rc2
[session initialization](https://github.com/torvalds/linux/blob/v7.3-rc2/tools/perf/util/session.c#L147)
and the [regular CMDLINE writer](https://github.com/torvalds/linux/blob/v7.3-rc2/tools/perf/util/header.c#L657)
provide a source-supported explanation: an empty stored command array produces
only the perf executable. The inspected ordinary record path does not populate
that array. This does not authenticate the installed writer or prove the cause
of this capture's metadata. Expected argv was not shortened to pass the check.

## Reproduce

Use the source revision and hashes in `receipt.json`, Python 3.12.15, the retained
capture, and the independently retained command JSON. Raw logs, paths and
capture bytes stay in ignored storage. `CAPTURE` and `COMMAND_JSON` are local
paths; the latter must contain the original independently recorded argv bytes,
not a vector copied from the perf header.

```sh
python3 -B evaluation/ordinary-perf-context-1c3e7ed/reproduce.py \
  --data "$CAPTURE" \
  --sha256 5b46da1edb6017ab187c2c7760054a43ef6bf4628d5d0fd0247f07fa70bf4aef \
  --command-json "$COMMAND_JSON" \
  --command-sha256 067de69478dbdd0ed7d4ce5eed23bd9f16461adfc0bd96902983cb2307ef0eaa
```

Exit 0 means report emission only. `observations.json` is the lossless numeric
output. `execution.json` retains exact commands with named path placeholders,
source bindings and closed-process receipts. Control commands are listed in
[PERF_DATA.md](../../tools/rapid-profiler/tree-work/PERF_DATA.md). Their executed
working bytes are joined to the source commit; the report ran at that commit.
The evidence commit changes no decoder or application executable source.

All seven required checks passed at that source revision in 504.194 seconds:
workspace 3,093 passed / 0 failed / 36 ignored plus two custom harnesses;
serial launch 1,039; staged allocation 3; prefixed pun 36; fmt, strict Clippy
and all-target/all-feature cargo check. Workspace took 351.459 seconds.
All eight historical exec-map/allocation regressions passed under default
parallelism. Rust 1.97.1, four build jobs, incremental disabled. Exact commands,
counts, durations and log hashes are in `receipt.json` and `checks.csv`.
These times describe validation cost, not application performance.

This increment supports claim 4's validation machinery. PMU meaning, historical
mapping identity, task/terminal accounting, accuracy and full A5 remain open.
The fixed-five strict 2-ms campaign remains FAILED, PASS, PASS, FAILED, PASS;
no sixth attempt was added.
