# Bounded perf probe: prerequisites refused, no capture

This adds a reproducible, bounded perf recipe and a same-PID launcher that
limits the application's actual output files to 1 MiB while retaining perf's
separate diagnostics. The planned workload is 3,072 native calls through the
ordinary C caller, with 1,536 helper returns and 614,400 original-body semantic
instructions. No perf sampling capture has run, and there is no performance
or accuracy result in this record.

All three whole launches are retained in `attempts.csv`:

| Source revision | Outcome before perf |
| --- | --- |
| `31629f6` | All 34 prerequisite stages passed, but the driver's required source inventory omitted `tests/call_tree_truth.rs`. The missing dependency was added; the full inventory comparator stayed unchanged. |
| `36f6389` | All 34 prerequisite stages and seven native limiter controls passed. The overflow control produced SIGXFSZ with its core bit set, despite the inherited zero core-size limit. The exact core-zero assertion refused it. |
| `06d173d` | The existing `normal-work` prerequisite failed its exact singleton task census after worker join. Seven preceding top-level stages passed. Perf and every decoder remained unrun. |

The intentional overflow fixture now disables its own dumpability, with checked
readback before writing. Its one separate development control observed actual
SIGXFSZ, core bit zero, exactly 1 MiB of output and empty stderr. The signal,
byte and core assertions were retained. A piped host core handler can bypass
RLIMIT_CORE, so that limit alone did not make the original fixture reliable.
This setup change applies only to the intentional overflow fixture.

The third failure remains unresolved at this revision. Source inspection places
the failed census after join, but the extra task's exact identity and kernel
exit phase were not captured. The working hypothesis is that a successful
pthread join can precede disappearance of its task-directory entry. The failure
was neither retried unchanged nor relabelled as success.

Each whole launch used a fresh four-CPU `cpuset-alloc` reservation with
AllowedCPUs enforcement for the complete owned process tree. Exact CPU sets,
before/after load averages, revisions and durations are in `attempts.csv` and
`receipt.json`. All three owners closed normally with no rescue or timeout.
Durations describe validation work, not workload performance.

At `06d173d0ef8bb9140d901552ab09168facde6fa2`, all seven repository checks
passed: workspace 3,088 passed, zero failed, 36 ignored, plus two custom
harnesses; serial launch 1,039 passed; staged allocation 3; prefixed pun 36.
All eight historical mapping regressions passed under the default workspace
harness. Strict Clippy, check and fmt passed. These checks do not substitute
for the refused workload prerequisite.

To reproduce the qualification at that revision, set absolute paths and a fresh
`$RAW` directory under `ignored/`, then run the tracked driver once:

```sh
cpuset-alloc run --cores 4 --sample-s 1 --tag li2-perf-probe -- \
  python3 -B "$REPO/tools/rapid-profiler/normal-work/perf_probe.py" \
  --revision 06d173d0ef8bb9140d901552ab09168facde6fa2 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use an outer process-tree owner with a 1,200-second wall limit and an 8 MiB log
limit, as recorded in the receipt. The driver requires the exact clean source
revision and records the complete source/tool inventory. The new limiter, capture and decode stages
have 20 CPU seconds and 30 wall seconds; inherited prerequisites retain their
own bounds (including 90/90 seconds for normal-state). APP output is capped at
1 MiB, recording at 16 MiB and each offline decode at 64 MiB. The fixed sampling event
is `instructions:uDS` at period 4,096, with no adaptive work, event fallback or
retry. Even successful capture and three decodes would remain
`CAPTURED_UNQUALIFIED` pending complete record/accounting validation.

This supports claim 4's validation infrastructure only. Raw logs, captures and
host paths stay under `ignored/`; tracked evidence is the compact receipt and
numbers. All earlier strict 2 ms deadline failures remain failures. The
software deadline guarantee, matched observer comparison and full A5 remain
open.
