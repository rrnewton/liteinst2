# Owned-neighbor frontends and validation

Tested revision: `76278bdfd19db60a0734ed1195d0f96d9da1a680`, on **AMD EPYC Zen 5 dev host**, Rust 1.97.1. This supports claim 4, systematic tactic validation, within the scopes below. The reporting commit is later than the tested revision.

The ELF frontend now accepts an explicit owned-neighbor planning profile. It uses complete selected-function owners and instruction heads, and records the profile in the indexed bundle. The common verifier and native consumer authenticate both owners for cross-function T3; the historical profile remains explicit. The separate [synthetic native result](cross-function-native-13fee48.md) covers installed and restored two-owner images.

| Validation command | Passed | Failed | Unchanged ignored |
| --- | ---: | ---: | ---: |
| Complete rewrite targets | 133 | 0 | 0 |
| Workspace | 2194 | 0 | 4 |
| Complete launch tests, serial | 995 | 0 | 0 |
| Core library, default test threading | 212 | 0 | 1 |
| Prefixed-pun oracle, default test threading | 28 | 0 | 0 |
| Neighbor-eviction oracle, default test threading | 72 | 0 | 0 |

Formatting, strict all-target/all-feature workspace Clippy, and all-target/all-feature workspace check passed. All three earlier address-space contention regressions passed in both workspace and relevant parallel runs. The workspace retains all 2,166 preceding group/name/status identities and adds 32; repeated observations across commands and nested summaries are not a unique-test total. Every phase retained equal source/tool/configuration observations and closed process records. Durations in the data are operational diagnostics, not performance measurements.

The [complete CSV/JSON data](data/cross-function-frontends-76278bd/summary.json) includes commands, identities, source pins, hardware and parser limitations. The [reproduction caller](reproductions/cross-function-frontends-76278bd/README.md) preserves exact commands and limits. The [earlier frontend attempt](data/cross-function-frontends-822c0a4-history/summary.json) retains its targeted passes, strict Clippy failure and all subsequent unrun commands. Its correction elided one redundant lifetime without suppressing the lint. A distinct failed reporting attempt and its exact example-header correction are also retained; they did not change or rerun validation.

The shared public log parser still refuses some observed harness forms. Complete independently reviewed inventories supply the published names/counts; parser diagnostics are kept in their own field. No test assertion, state comparator, resource bound or case selection was relaxed. This evidence does not establish a complete common-corpus campaign, a production router bootstrap, general native T3 qualification or full A3 completion.
