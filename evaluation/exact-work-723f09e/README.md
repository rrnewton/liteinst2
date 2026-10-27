# Exact original work and sample selection

A fixed 37-byte shared-library function now has independent original-work
truth, checked against its actual native instruction trace. The sampling client
keeps the complete call population and joins preassigned IDs to raw intervals
and generation reports, including calls after K closes. This supports claim 4's
systematic validation and the A5 selection-bias work; A5 is not complete.

Source: `46253eaa8ad9f8a8def8597c89f0d08ca5ceb481`. Tested source and recipe:
`723f09ea1331617139070e9d67465c9a5429e48d`, including main
`4f4e39bf9f1ab7efd4858ef0c3796829f71e61aa`. Hardware: **AMD EPYC Zen 5 dev host**;
Rust 1.97.1. Native fixtures use release binaries (opt-level 3, debug information
off, assertions and overflow checks on). Receipts pin the compiler, artifacts,
DSOs, source files and commands.

All 18 release reproduction stages passed. Four exact native pairs (eight
children) matched 800 original instructions, 130 conditional branches, 126 taken
branches, 130 input reads and four return reads. They passed 844 complete state
comparisons with no mismatches. The unchanged checksum regression separately
passed four pairs, eight children and 978 state comparisons, plus eight original
and eight instrumented functional calls. Both cohorts exercised actual outer
returns and the required short-RET refusal. All bounded child closures completed
without rescued descendants.

State comparison runs from gate entry through the post-POP boundary: inherited
GPRs, flags, XSAVE state, data, and the exact `[S-128, stack_end)` stack region.
Each real outer RET then executes after restoring that child's harness context.
Setup before readiness and the rest of the 64-KiB stack are outside this
comparison; the absolute child deadline still includes setup.

Twelve fresh processes each ran 24 original and 24 instrumented calls. All 288
instrumented calls have one raw row: 140 sampled and 148 after function sampling
closed. Every ID, expected result, stack return, raw prefix, owner and generation
report passed its check. The interpreter's ordered PCs, branch decisions and
operand reads are independent of the production scanner and relocation map.
Operand reads are reconstructed from exact semantics and native states, rather
than measured memory events.

| Schedule | Population mean instructions | K=1 error | K=10 error | K=24 error |
| --- | ---: | ---: | ---: | ---: |
| All short | 11 | 0 | 0 | 0 |
| All long | 389 | 0 | 0 | 0 |
| Alternating short/long | 200 | -189 | 0 | 0 |
| Ten short, then fourteen long | 231.5 | -220.5 | -220.5 | 0 |

Error is retained mean minus complete-population mean, in **original instruction
work units per invocation**. For the last schedule at K=10, all retained calls
are short: their mean is 11, despite the population mean of 231.5. Correct
same-call identities do not remove this selection bias. Raw RDTSCP endpoints
remain uncalibrated; no duration accuracy, PMU accuracy, cache-model result,
perf superiority or hook-overhead savings is claimed. Mandatory entry/RET hooks
remain active after the sample budget closes.

The seven required gates all passed at the tested revision: formatting, strict
workspace Clippy, all-target/all-feature check, workspace tests, serial launch,
staged allocation and the prefixed-pun oracle. Workspace tests: **2,531 passed,
0 failed, 4 ignored**, across 100 outer groups; five nested summaries are not
additional tests. The custom cleanup harness is separate. Default libtest
parallelism had 316 CPUs available; compiler jobs stayed at four. Only the
serial-launch command explicitly selects one test thread. Fourteen new Rust
model/join methods and five Python parser controls pass. Two initial development
attempts failed because the nested test module needed an explicit file path;
those failures remain recorded, with every test retained after the correction.
The earlier separate interrupt-fixture failure remains documented in
[the allocator report](../reachable-allocation-48f2225/README.md); this run does
not claim its root cause is fixed.

[intervals.csv](intervals.csv) contains all 288 raw numeric rows;
[populations.csv](populations.csv) retains exact error fractions.
[native-pairs.csv](native-pairs.csv), [exact-truth.csv](exact-truth.csv) and
[checksum-intervals.csv](checksum-intervals.csv) record the required regressions.
[commands.csv](commands.csv) records exact commands and operational durations;
these durations are not performance measurements. [receipt.json](receipt.json)
records provenance, scope, build profiles and hashes. Logs and captures stay
ignored. Full raw machine-state and Report objects are checked by the bound
native/runtime code; the CSVs are compact projections of those checks.

To reproduce, check out the tested revision, select its Rust toolchain and use
the native and workspace commands in receipt.json's `reproduction` object. The native command is
`python3 -B tools/rapid-profiler/verify_ordinary_interval.py --exact-work` with
its required revision, output, toolchain, user-home and cargo-home arguments.
The workspace command uses `evaluation/admission/check_exec_identity.py
--checks-only`. Both require a new output directory under ignored/.
