# Original nested frames joined to finalized records

At exact source `12e50f491139b8a5cb4058b273acddf263de0dd8`, one release
qualification passed all **192 pairs, 384 record rows and 18,756 full-state
comparisons**, with zero mismatches. All 37 stages closed normally, including
384 normal child reaps; no rescue reaping. The preceding controls passed
376 tests with one existing hardware ignore. Native elapsed time was
474.860 seconds within the unchanged 510-second limit. This is claim 4
functional evidence, not a throughput measurement or completion of A5.

Hardware: AMD EPYC Zen 5 dev host. CPUs 1/128/129 were hard-reserved; the native
parent and tracees used CPU 128. Cohort load averages were 41.84/55.90/64.22
before and 55.27/50.02/57.35 after. Four compiler jobs, incremental disabled;
exact Rust version, commands, limits, reservations and hashes are in
`receipt.json`. The outer owner closed in 691.175 seconds. Root authenticated
all 1,176 source pins and 320 retained files (59,636,134 bytes) after closure.
Raw logs, binaries and captures stay ignored.

The new candidate-only postflight packet copies actual immutable batch records,
Reports and history. The parent interprets it after both normal reaps and joins
it to independently counted original frames and the existing paired state
trace. `work.csv` contains all 384 resulting rows; `pairs.csv` and `coverage.csv`
retain the complete 192-pair and 12-group numeric results. No second candidate
trace, reconstructed SDK owner or timestamp-truth claim is introduced.

If P and C count parent and child body instructions including their own RET,
parent own/inclusive/pre-RET counts are P / P+C / P+C−1; child counts are
C / C / C−1. Subtracting the pre-RET spans numerically gives P, but that span
includes the child's RET and excludes the parent's RET. It is not an exclusive
elapsed cost. RemovedChild still contributes an executed frame and an
unsampled record. Re-arming changes generation ownership, not frame extent.

## Validation outcomes retained

| Check | Result | Completed pass observations | Seconds |
| --- | --- | ---: | ---: |
| Formatting | PASS | — | 9.750 |
| Strict workspace Clippy | PASS | — | 39.271 |
| Workspace check | PASS | — | 7.383 |
| Workspace tests | TIMEOUT | 1,982 | 360.179 |
| Serial launch | TIMEOUT | 804 | 180.074 |
| Staged allocation | PASS | 3 | 4.539 |
| Prefixed pun | PASS | 36 | 5.515 |

Each command ran once at the exact native source. The fail-stop sequence's
unstarted tail ran separately once; after serial launch timed out, only its
two unstarted allocation checks ran. Workspace and serial launch keep their
original 360/180-second bounds and failed status, with nine/two rescue reaps.
All outer owners closed normally without rescue. Prefix counts can include
nested summaries; zero reported assertion failures is not full-suite success.
The workspace prefix includes all three historical observing-control allocation
regressions. No whole-workspace or 316-thread pass is claimed. Each phase's
eight-CPU reservation and load are recorded.

Development results include every invocation: the first Rust run accidentally
loaded the old controls twice. Its 24 reported passes are explicitly unaccepted
as new-join coverage. Correcting the module path produced exactly 17 shared
controls; all 38 relevant application controls and 30 Python controls passed.
The admission inventory fix at the separate `inventory_revision` in the receipt
preserves all old hashes, inverses and assertions while requiring the eight new
controls in each harness. Its five targeted controls and full 350-control
Python suite passed. It does not relabel native evidence to another revision.

The earlier [fixed-five session campaign](../ordinary-call-pair-session-a6c8297/README.md)
remains one PASS and four FAILED. It was not rerun. The strict 2 ms arm,
10 ms period and 2 s shutdown requirements remain unchanged.

## Reproduction

Use the exact native source, explicit local paths and the tracked
[freeze/launch protocol](../ordinary-call-pair-native/ROOT_PROTOCOL.md).
It performs one complete 192-pair qualification with the existing limits.
Do not repeat an attempt or substitute a partial population. All three output
tables are required by the source-bound native and session readers.

For checks, use `evaluation/admission/check_exec_identity.py --checks-only`
under the eight-CPU allocator command recorded in the receipt. If its final
three checks remain unstarted, the existing
[tail generator](../ordinary-call-pair-native-cfc8d76/reproduce_tail.py)
materializes that exact runner. If serial launch then fails, use
`python3 -B evaluation/ordinary-call-pair-work-12e50f4/reproduce_allocation_tail.py`
to materialize only the two remaining checks, and the recorded allocation-phase
command to execute them once. The generators do not run tests or authorize
repeating a failed command. Keep every failure. Allocator revision and all
commands with local path placeholders are recorded in `receipt.json`.
