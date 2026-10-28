# Eight-call source-batch native qualification

The first release attempt passed at source revision
`b7166e8a35951958e9f0247e27e0694fb45cfd35` on the AMD EPYC Zen 5 dev host
(AuthenticAMD family 26, model 17, stepping 0). This supports claim 4 for the
fixed source-batch population. Both original and installed SDK owners complete
eight admitted calls and finish before normal child exit.

| Observed result | Count |
| --- | ---: |
| Fit2/Conflict3 × two seeds, original/installed pairs | 4 |
| Normally exited and reaped batch children | 8 |
| Actual root invocations | 64 |
| Full-state comparisons on calls 1 and 8 | 2,744 |
| Mismatches | 0 |
| Authenticated hardware stops | 304 |
| Actual application CALL/RET transfers | 192 |
| Actual outer CALLs / outer RETs | 64 / 64 |
| Source-attested successful batch finishes | 8 |
| Installed rows / journal events / report records checked | 64 / 128 / 64 |
| Cleanup rescues across all nine stages | 0 |

Each selected call compares 343 ordered states: 332 application visits and
11 gate boundaries. The comparisons include registers, flags, segments, TLS
bases, canonical XSAVE, complete immutable source/images and input, and the
unmasked application stack. Original operand traces are independently inspected
for these selected calls. Calls 2–7 receive scalar, frame and physical-transfer
checks, with RF required clear after every actual middle CALL/RET step. They
receive no full-state or operand-trace credit.

Every original child used 716 explicit steps: 343 on each selected call and
30 across the middle six. Every installed child used 11,098: 5,526 on call 1,
5,542 on call 8 and 30 across the middle six. Each child retained one continuous
20,000-step ceiling, and each pair retained one absolute 15-second deadline
from before allocation. CONT instructions are not explicit steps. The whole
four-pair native stage completed in 10.320 seconds; that is an operational
validation duration, not a throughput measurement.

The child checks complete row identities, all 512 journal words, report
admission/outcome/history, retirement, detach totals and unchanged input before
normal exit. Finishes and these object joins are source-attested; the four-row
CSV does not independently export those objects. The actual hardware-stop
prerequisite also passed at this revision, with two RF-exposing stops, two NOP
steps with RF clear, exact debug-state restoration and unchanged fixture state.
Eight hardware controls, four batch controls, four hardware parser methods and
ten batch parser methods passed in the same nine-stage run.

```sh
python3 -B tools/rapid-profiler/tree-work/verify_hardware_stop.py \
  --batch-state --revision b7166e8a35951958e9f0247e27e0694fb45cfd35 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use a fresh `$RAW` beneath the checkout's `ignored/` directory and canonical
absolute local paths. The checkout must be clean at the exact revision. Rust
1.97.1 used optimization level 3, debug info off, assertions and overflow checks
on, with four build jobs. The receipt records commands, tool and artifact hashes,
Cargo freshness and the digest of 348 source inputs. Root joined every input
back to Git and checked all nine closed process receipts and stream hashes.
Every stage required exit zero, ECHILD and no unexpected descendants or cleanup
events. Private manifests, requests, logs and binaries stay ignored.

This establishes finite batch correctness with selected full-state coverage.
It supplies no general workload, full-middle-call state, hardware-cache,
clock-accuracy or performance claim. The separate owner qualification covers
batch abandonment, incomplete finish and lifecycle failures.

Merged revision `eefaefefc8e35563c64c3baa90297eb0967ffea0` includes main
`7cdc68012a7bdecfd52d6b70e4318b60c51e9cab`. All 348 native qualification inputs
are byte-identical to the tested revision above; the native result is inherited
by that source comparison, not reported as a second run. The seven required
checks passed on the merged revision:

| Check | Result | Wall seconds |
| --- | --- | ---: |
| Formatting | PASS | 6.186 |
| Strict workspace Clippy | PASS | 30.182 |
| All-feature/all-target workspace check | PASS | 3.666 |
| Default workspace tests | 2,878 passed, 0 failed, 32 ignored | 337.916 |
| Serial launch | 1,039 passed, 0 failed | 129.826 |
| Staged allocation regressions | 3 passed, 0 failed | 0.037 |
| Prefixed-pun oracle | 36 passed, 0 failed | 1.329 |

Workspace testing retained the full 316-CPU affinity and default libtest
parallelism. The 20 newly ignored cases are the 19 fresh-process owner cases
qualified in `evaluation/tree-batch-owners-b291ef8/` and the hardware prerequisite
qualified here; no inherited test was made ignored. Nested child summaries do
not count as additional workspace tests. Every command completed normally with
zero cleanup rescues. Reproduce these checks with the command in
`merged-gates.json`; their durations are operational validation measurements.
