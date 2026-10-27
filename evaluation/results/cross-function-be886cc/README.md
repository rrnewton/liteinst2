# Two-owner T3 planner validation

All required checks passed at `be886cc1637630985bef497ad2d6376facdb883f`, based on coordinator main `7861db9c4ad2c8be1144265014794afe070fbd61`, using Rust 1.97.1 on **AMD EPYC Zen 5 dev host**. The change lets the artifact planner continue T3 search through explicitly authenticated function owners while preserving the predecessor composition, local failures and cumulative search budgets.

| Command | Passed | Failed | Ignored | Seconds |
|---|---:|---:|---:|---:|
| Targeted planner contracts | 23 | 0 | 0 | 16.203 |
| Workspace tests | 2,162 | 0 | 4 | 345.533 |
| Serial launch tests | 995 | 0 | 0 | 125.285 |
| Default-parallel library tests | 212 | 0 | 1 | 1.723 |
| Default-parallel prefixed-pun oracle | 27 | 0 | 0 | 1.384 |

Fmt, strict workspace/all-targets/all-features Clippy and all-targets/all-features check also passed. The workspace test retained its 360-second bound. These elapsed times include the recorded command's build/test work and are operational observations, not benchmark comparisons. Repeated commands exercise overlapping tests; their counts must not be added into a unique-test total. All 2,018 prior workspace identities and statuses remain, with 148 additions and no removed or changed status. Nested child summaries and unsummarized starts receive no extra pass credit.

All three allocation regressions passed: `dropping_staged_image_releases_its_exact_mapping`, `observing_control_staged_drop_unmaps_before_releasing_last_owners` and `native_state_covers_every_prefixed_pun_and_original_successor`. The independent default-parallel library and prefixed runs also passed. Source, tools and configuration matched before and after every phase; process cleanup completed without leftover descendants.

`cases.json`/`cases.csv` preserve every outer case identity and status; `groups.json` and `terminal-observations.json` keep outer counts separate from literal nested terminals. `commands.json` retains full commands, environment, affinity, limits and closure evidence with reversible private-path roles. `parser-results.json` preserves limitations of the unchanged public log parser; reviewed complete outer inventories supply the separate count authority. Raw logs remain ignored.

The [validation driver and instructions](../../reproductions/cross-function-be886cc/README.md) reproduce the five phases at the exact tested revision. Debug information was disabled to limit disk use; debug assertions and existing test limits were unchanged. The collector only regenerates saved-record reports. Its missing-log and missing-inventory refusal controls passed; [reporting.json](reporting.json) preserves their exact assertions, commands, source hashes and closures. Their [source](../../reproductions/cross-function-be886cc/collector-controls.py) requires the recorded private input envelope; these controls execute no validation workload.

This evidence supports claim 4's planner and regression coverage. Native execution of the new cross-function T3 path, the common-core corpus and full A3 qualification remain pending. The earlier E9 controlled replay results and failures retain their separate tested revision.
