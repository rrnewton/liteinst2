# Fixed-five nested-call qualification: one pass, four failures

Exact source: `a6c8297fa4466ac1ac4016fc07f2349ae00c1db3`. Hardware: AMD EPYC
Zen 5 dev host; Rust 1.97.1. Release optimization 3, assertions and overflow
checks enabled, four compiler jobs. Claim 4 functional validation; A5 remains
open. Durations here describe validation commands, not application throughput.

The source correction adds the native owner's complete source inventory to the
session recipe, fixing the missing README that previously prevented native
prerequisite acceptance. Session consumers now authenticate the identical
tracked launcher directly. A separate change reuses the legacy oracle's actual
full register observation at the same uninterrupted ptrace stop, preserving
all comparisons and bounds. It removes one redundant GETREGS and its potential
infrastructure failure. Both changes received independent source approval.

All five predeclared qualifications ran once at this revision:

| Qualification | Passing cases | Failed cases | Unrun | Outcome |
| --- | ---: | ---: | ---: | --- |
| 1 | 64 | 0 | 0 | PASS |
| 2 | 62 | 2 | 0 | FAILED |
| 3 | 63 | 1 | 0 | FAILED |
| 4 | 63 | 1 | 0 | FAILED |
| 5 | 63 | 1 | 0 | FAILED |

All 32 original references and eight malformed-input controls passed. Across
320 installed cases, 315 passed and five failed. All 395 stages closed normally;
all 320 application children were normally reaped, with no rescue. The first
qualification is a complete pass; the overall campaign is **FAILED**. The
315 passing cases contain 101,265 roots and 202,530 target rows (196,097 sampled,
6,433 unsampled). These partial aggregates do not qualify the failed campaign.

All five failures were real `clock poll: Deadline` refusals while waiting for
more input in `partial_open_record` or `record_cap_without_eof`. No timeout,
census, comparator or strict 2 ms arm / 10 ms period / 2 s shutdown gate was
changed. No replacement attempt occurred.

| Qualification | K | Case | Poll gap (ns) | Requested wait (ns) | Actual wait (ns) |
| --- | ---: | ---: | ---: | ---: | ---: |
| 2 | 10 | 29 | 8,451,731 | 1,000,000 | 8,450,299 |
| 2 | 1000 | 27 | 13,263,708 | none | none |
| 3 | 1000 | 29 | 10,221,569 | 1,000,000 | 10,220,147 |
| 4 | 10 | 29 | 13,232,940 | 1,000,000 | 13,231,558 |
| 5 | 1000 | 27 | 11,583,297 | 1,000,000 | 11,581,805 |

Each affected controller interval records one involuntary context switch via
`RUSAGE_THREAD`; thread CPU deltas are only 673–1,592 microseconds. The second
failure's long span was between poll return and arm processing, rather than
inside the wait. These observations are consistent with scheduler delay, but
are not a complete causal scheduling trace. The current strict wall-clock
contract was not reliable in this reserved shared-host campaign. CPU reservation
alone did not establish a 2 ms scheduling guarantee. This finding remains a
failure, rather than grounds to discard a case or retry until green.

Controller/worker/producer CPUs 62/70/73 were hard-reserved through cpuset-alloc.
Owner load was 30.22/39.60/47.99 before and 45.22/51.63/52.51 after; recipe load
was 30.23/39.30/47.80 to 43.41/51.39/52.44. The owner closed normally with exit 1
in 2,321.748 s, within its original 7,200 s limit. Root rechecked 6,899 source,
tool and evidence pins after closure, joined all 320 actual application
identities/stream hashes/reaps, revalidated all 315 complete transcripts against
the independent references, and retained all 762 outcome records. Raw captures
remain ignored; the CSVs retain every stage, installed case and qualification.

The same-revision native prerequisite **passed** all 192 pairs, 12 coverage
groups and 18,756 state comparisons: zero mismatches, 768 target CALLs/RETs,
384 outer RETs and 384 normal reaps. The session recipe actually accepted this
prerequisite before launching subjects. All 37 native stages closed normally,
with 356 preceding controls passed and one existing ignore. Native elapsed was
476.646 s within the unchanged 510 s bound. CPUs 65/123/139 were reserved,
tracer/tracees on 123; native load 43.04/57.10/55.81 to 32.75/42.52/49.52.

Formatting, strict workspace Clippy and check passed. Workspace testing
**failed** its original 360 s bound (360.135 s; seven rescue reaps), after 1,982
completed pass observations, zero reported assertion failures and one ignore.
These are prefix observations and can include nested summaries. The three
checks left UNRUN then ran once: serial launch 1,039 passes in 130.688 s, staged
allocation three, prefixed pun 36. Both phases reserved eight CPUs. A separate
four-CPU targeted quiescent-oracle run passed all 39 tests. No full-suite or
316-thread pass is claimed.

Development evidence records all 12 invocations: ten passed and two post-closure
auditor implementations failed. Their corrections joined sources from the
already authenticated protocol and compared the producer's canonical JSON
serialization instead of Python tuple/list objects. No subject reran. The
campaign/receipt/producer controls passed 17 cases, and owner controls four.
Exact commands and base-plus-changed-source hashes are in `development.json`;
all outcomes are in `development.csv`.

Reproduce the run at the exact source with the tracked
[native protocol](../ordinary-call-pair-native/ROOT_PROTOCOL.md), then the
[session protocol](../ordinary-call-pair-session/ROOT_PROTOCOL.md). Keep five
qualifications, all 320 installed cases, fresh destinations and every original
limit. Use allocator revision `d0c2867be75b495eb64239e664c6306af9747783`.
`receipt.json` and `session.json` record exact commands, tool/receipt hashes,
roles, load and release settings. `$REPO`, `$TOOLCHAIN`, `$AGENT_UTILS`, `$PYTHON`,
`$USER_HOME`, `$CARGO_HOME` and `$RUNTIME_DIR` stand for explicit local paths.

To reproduce `deadline-failures.csv` from these retained closed captures:

```sh
python3 -I -B evaluation/ordinary-call-pair-session-a6c8297/analyze_deadlines.py \
  --capture "$CAPTURE" --raw "$RAW"
```

`CAPTURE` is this session owner's directory and `RAW` its campaign directory,
both specified by the recorded launch request. The extractor checks the exact
owner/result hashes and closed custody before reading diagnostics. New runs use
the public freeze/launch scripts; this extractor reproduces these recorded
numbers. Workspace reproduction uses `evaluation/admission/check_exec_identity.py
--checks-only` and the recorded arguments; the existing
[tail generator](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py) reconstructs
only the three checks left UNRUN. Earlier failures remain recorded separately.
