# Short-neighbor merged-tree checks

Revision `9adb4512cb2151c1976b4a34ef15f1f222eb33a8` includes main
`97d14d89e1d32f3c0f08233d687053d8c1a13bcc` and the short-neighbor work.
Hardware: AMD EPYC Zen 5 dev host. Claim 4 evidence remains partial:
**the full workspace did not finish within its unchanged 360-second limit**.

| Check | Outcome |
| --- | --- |
| Formatting | PASS, 8.03 s |
| Strict workspace Clippy, all targets/features | PASS, 36.30 s |
| Workspace compilation, all targets/features | PASS, 2.90 s |
| Workspace tests | TIMEOUT, 360.10 s; cleanup completed, five descendants reaped |
| Serial launch, exact tracked command | PASS, 1,039 tests in 27 harnesses, 127.46 s |
| Staged allocation regressions | PASS, 3 tests |
| Prefixed-pun oracle | PASS, 36 tests |
| Merged inventory controls | PASS, 5 tests, 71.89 s |

Before the workspace cutoff, 69 completed libtest harnesses reported 1,992
passes and one unchanged ignore. The incomplete neighbor harness logged 80
more passing tests: all existing tests, with none of the new short-neighbor
controls yet reported. There were 2,072 completed pass observations and no
reported failed test. These counts do not qualify the workspace or the
99-test neighbor harness. The independent [new native population](../short-neighbor-c2696f8/README.md)
passed separately; its three source files are byte-identical here. The earlier
full 350-control recorder timeout is also retained.

The serial receipt parser accepted the complete 27-harness population and
native protocol: 50 native cases, 15 dynamic admission fixtures, 388 matrix
cases, 110 validation fixtures and the complete backing-cleanup helper record.
This establishes that command's completion, not an all-green validation run.
The allocation checks include both previously flaky staged-drop cases and
`native_state_covers_every_prefixed_pun_and_original_successor`. CPU affinity
was four reserved CPUs; this is not a 316-thread harness campaign.

Two failed checks remain in [checks.csv](checks.csv) and
[receipt.json](receipt.json). Strict Clippy first rejected an indexed test
loop on merge `4447179325709bc16b60d6a0cbfd222369f9a172`; the correction uses
`enumerate` over the same original bytes with the same assertions and no lint
exemption. The first serial command omitted the cleanup helper's required
`--nocapture`; it failed on that argument contract. The corrected invocation
is exactly the tracked runner's `--tests -- --test-threads=1 --nocapture`.
No failed outcome was renamed as a pass.

Independent source reviews approved the history-chain merge and loop correction.
Both lanes' source checks, historical catalog counts and assertions remain.
Current declarations are core278/1, native99, workspace3608/37 and Python350;
these declarations are not successful-run counts.

Reproduce with the tracked [admission runner](../admission/run.py), using its
[bounded protocol](../admission/README.md) and the exact revision above. The
receipt contains every actual command, limits, tool hashes, CPU reservations,
load averages and cleanup result. Raw logs remain ignored. Sources were clean
throughout these checks; only the separately recorded native-evidence files
were untracked. All measurements are validation duration, not performance claims.
