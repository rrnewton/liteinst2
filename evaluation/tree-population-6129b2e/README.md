# Complete caller/child populations

At source revision `6129b2e6934ca1f076e51df6b58e4754cea48410`, three fresh
release processes each completed 24 original and 24 installed root calls over
ten `fit2` inputs followed by fourteen `conflict3` inputs. Both functions keep
their first K intervals. The complete population remains visible after K closes
admission, so selected samples can be compared with all calls.

| K | Retained nodes | Closed nodes | Retained conflicting calls per function | Conflicting-call fraction error |
|---|---:|---:|---:|---:|
| 1 | 2 | 46 | 0 | -14/24 |
| 10 | 20 | 28 | 0 | -140/240 |
| 24 | 48 | 0 | 14 | 0/576 |

The three CSVs preserve all 144 node observations, including 74 closed nodes.
Every run checked three complete journal pages, real returns, complete retained
Reports and unchanged guarded inputs. Each root has 332 inclusive original
instructions, including its child's 326; root-exclusive work is six instructions.
These counts describe separately qualified fixed source, not an instruction
trace of these ordinary calls. The retained-label error is not a hardware cache
miss or timing error; raw callback timestamps remain uncalibrated.

All 47 release stages passed, including the 44 inherited stages, four tree
state pairs with 1,372 comparisons, ownership transitions and the malformed
return-word refusal. All parents exited normally, with zero rescued descendants.
The release profile uses opt-level 3 with assertions and overflow checks enabled.
Hardware: AMD EPYC Zen 5 dev host. The receipt records exact commands, tool
versions, CPU fields, artifact hashes and bounds. Raw logs remain private.

Reproduce using the [tree recipe](../../tools/rapid-profiler/tree-work/README.md)
with all listed flags plus `--tree-population`, from the exact clean source
revision. The parser controls and workspace-check recipe are recorded in
`controls.json` and `gates.json`. Eight parser controls pass. Workspace validation
at default 316-CPU affinity passed 2,833 tests (12 ignored); serial launch passed
1,039, staged allocation three and prefixed-pun 36. Formatting, strict Clippy
and the all-target/all-feature check passed. Command durations are operational
validation records, not performance measurements.

Initial development attempts failed on an unused-method lint and Python 3.9's
lack of strict zip. Their private receipt digests and corrections remain in
`receipt.json`; neither failure earns result credit. Earlier tree and workspace
failures remain recorded in the [preceding evidence](../call-tree-c2db968/README.md).
This increment supports claim 4. General call graphs, calibrated timing, perf
accuracy, real-application coverage and the full A5 release gate remain open.
