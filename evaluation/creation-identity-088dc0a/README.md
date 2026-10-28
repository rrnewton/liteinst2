The creation-identity fix is `88d1b9076c26d2877572859de33f56814eb204ab`.
The final recipe/source revision is `088dc0a3662a4661328604db6e96f28c7cd80775`.
**The final seven required gates passed at that exact revision.** Workspace
finished with 2,546 passed / 0 failed / 5 ignored in 333.363 s; serial launch
passed in 124.510 s. The earlier 13-command campaign remains FAILED. The
creation-identity fix is qualified; the separate backing-child failure remains
unresolved, with no claim that its cause was fixed.

A cancellation race allowed `PTRACE_GETEVENTMSG` to return EXIT status `9`
after the caller had consumed a creation stop. The old code treated that number
as a child identity. The diagnostic failure retained that extra numeric owner
after both real tasks had matching terminal/reap records. The forced native
control reproduces this stale-message condition against the old implementation.

Both creation consumers now authenticate a candidate in the original tracer's
non-consuming `waitid(P_PID, ..., __WALL | __WNOTHREAD)` domain before retaining
numeric authority or a pidfd. Nonpositive, retired and private-helper identities
refuse. Success with no ready status admits an eligible but delayed child;
later lifecycle/state joins, terminal comparisons, global ECHILD and pidfd-HUP
checks remain. This relies on the exclusive tracer/no-foreign-reaping contract:
WNOWAIT alone does not reserve arbitrary PIDs. Exact Linux v7.1.3 source URLs and
hashes are recorded; this does not authenticate a running kernel binary.

| Closed observation | Actual outcome |
|---|---|
| Original workspace | FAILED at creation cleanup; library terminal 741 passed / 1 failed |
| Failure-only diagnostics | 25 focused PASS; next default library FAILED, 741/1 |
| Old-implementation forced control | FAILED as expected, 0/1 |
| Helper/thread-guard mutant | FAILED as expected, 1/2 |
| Fixed source | 3 identity controls PASS; five default libraries each 745/0 |
| 13-command campaign | FAILED at workspace after 3 static and 6 creation-specific command successes; final 3 commands UNRUN |
| Its workspace failure | Backing child exited 1; test parent SIGABRT |
| Temporary backing diagnostics | 25 custom runs PASS; diagnostic workspace PASS in 330.881983 s |
| Final seven checks after diagnostic revert | PASS at the same exact revision; workspace 2,546/0/5, serial launch PASS, allocation regressions PASS |

The diagnostic workspace used **only temporary diagnostics**, later removed; it gives
no backing-fix credit. Its outer libtest count is 2,546 passed / 0 failed / 5
ignored in 100 terminal-bearing groups (101 Cargo heads; five nested summaries
excluded). The custom cleanup harness's five controls/six trajectories are
separate from libtest counts. Its passing repetitions do not explain the earlier
panic. A join/singleton interaction remains a hypothesis, not a proven cause.
The separate unresolved `orig_rax` fixture issue remains in the
[prior report](../reachable-allocation-48f2225/README.md).

`commands.csv` preserves every attempt as an observation, with normalized argv
in `receipt.json`'s command catalog. Record ID/index locates the exact saved parent
under the pinned metadata hash; every log is hashed. All parents closed with
cleanup complete and zero rescued descendants. Countercontrol failures are not
renamed passes. The two diagnostic patches and guard-mutant patch preserve the
source variants; old-code execution also used additive tests, so it is not
labelled an unmodified checkout. Raw logs and process identities stay private.

At the same tested revision, after reverting the temporary diagnostics, the
final required qualification uses seven checks only:

```sh
env -u PYTHONOPTIMIZE python3 -B evaluation/admission/check_exec_identity.py \
  --checks-only --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_REQUIRED_GATES"
```

Those checks are fmt, strict Clippy, workspace check, workspace test, serial
launch, staged allocation and prefixed-pun. Only serial launch requests one test
thread. The earlier `--include-creation-identity` campaign remains FAILED:
three identity controls and five default library runs passed on this same source,
then workspace failed and the last three commands were UNRUN. Their six successful
creation-specific commands are retained; the final seven-check run need not
repeat them and cannot turn the earlier campaign into a 13-command PASS.

Hardware label: AMD EPYC Zen 5 dev host; observed CPU fields, 316 available CPUs,
Rust 1.97.1 and four compiler jobs are recorded. These are functional results;
command seconds are not performance measurements.

This export was generated from the closed historical records and the final
seven-check receipt (SHA-256
`ef20a39b08b449f6e1f600e3884a8f88c673a2e77c971440263d6a789113aa6d`):

```sh
python3 -B project.py --records "$CLOSED_A5" --out "$NEW_PROJECTION" \
  --final-gates "$CLOSED_FINAL" \
  --final-gates-sha256 ef20a39b08b449f6e1f600e3884a8f88c673a2e77c971440263d6a789113aa6d
```

The projector opens no products or live state and executes no subjects. It
requires the exact revision/recipe, `--checks-only`, the seven named commands
and their unchanged bounds, all successful. It records that separate
qualification without overwriting any failed attempt. README/projector are
authored sources.
