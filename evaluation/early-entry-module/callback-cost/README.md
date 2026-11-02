# Optional-entry callback cost

The strict 20,000-step state profile remains FAILED after the first physical return and second entry-flag load. This revision preserves every witness word and comparison while avoiding an intermediate 4,096-byte journal copy on the qualification observer path. The production callback also reads the journal count only when needed. Static disassembly establishes the copy removal; it does not establish a runtime speedup.

At revision `89b9fe5de6872ca260884f85460d46553ce04b98`, all four default-feature native integration cases passed, and the source/library checks passed 567 tests with the same 37 ignores. Strict qualification attempted one cohort; eleven were unobserved, with no completed pair. The literal failed plan and all earlier outcomes remain in the receipts. The separate 80,000-step profile passed all 12 cohorts: 288 pairs, 576 children and 139,872 state comparisons. Every candidate trace still exceeded 20,000 steps. Resource admission completed after eight samples. All five full-gate commands passed. The workspace passed 4,538 top-level tests plus 11 controlled child runs, with the same 43 ignores; the serial launch suite passed 1,039 tests. All 27 critical regressions and 21 short-neighbor cases passed.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.

`receipt.json` records exact tools, commands, profiles, source manifests, hardware, ownership and prior publication pins. The sibling `../reproduce.py`, `../state.py`, `../state_wide_80k.py` and `../workspace.py` retain separate native, strict, wide and workspace recipes. Use fresh output directories and the recorded reservations and bounds. There is no timing or complete A4/A5 claim.

`inspect.py` reproduced the three reviewed disassembly captures byte for byte at the recorded revision and ELF hash. It writes captures only under ignored/target paths. Use its installed location and a fresh `--name`; it neither builds nor executes the subject.
