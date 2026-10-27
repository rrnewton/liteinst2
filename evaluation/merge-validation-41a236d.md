The merge of main `725f38314244d171d71c9f5915d27afbf611e25d` into the
core branch was validated at `41a236dff00295a70b5c4cf2982eb91359e5b2c1`.
Reporting commit `f1ea106541a40d6afb74936cd60860552d8dc04a` adds only the
reproduction and collection scripts. No runtime or test assertions changed
between the tested merge and the reporting commit.

All twelve commands passed on the AMD EPYC Zen 5 dev host (EPYC 9D85), using
Rust 1.97.1 and four Cargo build jobs. Required gates used four CPUs and four
test threads. The repeated parallel sequence used eight-CPU affinity with
`RUST_TEST_THREADS` and the private child selectors absent from its parent
environment. The serial launch command explicitly used one test thread.

| Check | Result | Operational time |
|---|---|---:|
| `cargo fmt --check` | PASS | 6.11 s |
| Strict workspace/all-target/all-feature Clippy | PASS | 24.58 s |
| Required workspace tests | 1,994 passed; 4 unchanged ignores | 337.11 s |
| Workspace/all-target/all-feature check | PASS | 13.59 s |
| Serial `liteinst-launch --tests` | 865 passed | 138.84 s |
| Three complete library runs | 207 passed; 1 unchanged ignore each | 6.04 / 1.62 / 1.67 s |
| Three complete prefixed-pun oracle runs | 27 passed each | 7.99 / 1.47 / 1.72 s |
| Complete default-parallel workspace | 1,994 passed; 4 unchanged ignores | 359.14 s |

There were no failures or unrun commands. Test totals describe outer libtest
cases; nested child output and the separate ordinary-main cleanup controls
are not added to them. Repeated runs overlap and are not unique-case totals.
The two staged-drop mapping tests and
`native_state_covers_every_prefixed_pun_and_original_successor` each passed
in four default-parallel invocations that included them. This checks the
previous `NoReachableMapping` and `AllocationUnavailable` regressions with
their existing assertions and isolation mechanisms intact.

The 360-second workspace limits and 180-second serial limit were unchanged.
Serial cleanup completed with zero adopted descendants. Each enclosing caller
was waited for and exited zero. Times include operational overhead and are
not performance measurements; CPU time was not measured.

[Raw command results](results/merge-validation-41a236d-20261026/commands.csv),
[complete normalized command contexts](results/merge-validation-41a236d-20261026/commands.json),
[revision, hardware and closure summary](results/merge-validation-41a236d-20261026/summary.json)
and [outer test accounting](results/merge-validation-41a236d-20261026/outer-counts.json)
retain the public evidence. Raw logs and original path contexts remain private.
[Reproduction instructions](merge-validation-reporting.md) reconstruct the
saved callers and collect their results.

This provides partial support for claim 4, systematic tactic validation,
within these test scopes.
It does not complete A3 or its common-corpus application/state-equivalence
gates. The previously recorded common-corpus production failures remain
failures; this merge check does not replace those results.
