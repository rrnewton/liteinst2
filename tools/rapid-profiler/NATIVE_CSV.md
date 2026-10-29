# CSV body under the ordinary-call state oracle

`frontend-native-oracle normal-csv-state` compares the original and instrumented
CSV body through the existing 67-byte C caller. Two fixed seeds each exercise all
16 records: 32 pairs, 64 children and normal reaps, 128 target calls and returns,
and 64 caller returns. Each child makes two equal requests. This route does not
qualify the separate Rust caller used by `normal-csv-work`.

```text
frontend-native-oracle normal-csv-state CANDIDATE TRUSTED_FINAL ELF_VA LENGTH CALLER_CANDIDATE CALLER_FINAL OUTPUT
```

The complete independently retained CSV ELF extent must fit the new certified
block profile, 5–256 bytes. The old whole-function limit remains 80 bytes. Both
DSOs require the existing strict scalar loader contract, including eager binding.
Candidate and trusted files are distinct, immutable files. The caller retains
its exact existing byte and CALL/RET contract. An incompatible compiler result
is refused; selecting a shorter portion of the function is not permitted.

Each pair keeps the existing non-resetting 15-second deadline and 20,000-step
limit per child. Continuous execution compares complete supported register,
defined-flag, XSAVE, data, stack and source state at the existing logical
boundaries. Actual CALLs, saved return words, caller effects, callee-save
restoration and the final caller RET remain checked. Instrumented children also
validate both sampled records, every journal word, Reports, history, checkpoint
and detach. The parent requires both normal exit-zero reaps before accepting a
pair. A dedicated child aborts on a failed assertion before unwinding its owners.
An external owner must bound and clean up the entire process tree.

The output directory contains `normal-csv-pairs.csv` (32 ordered rows) and
`normal-csv-coverage.csv` (two rows), followed by one complete terminal on stdout.
Every declared RET must be observed for each seed. Head and edge counts describe
the paths observed; they do not claim complete CFG path coverage. Partial files
or a printed terminal cannot override a failed exit, incomplete cleanup or the
final deadline check.

This supplies a qualification route and refusal controls. Native outcomes must
be established by a separately recorded run at an exact revision. No timing,
performance, arbitrary-input or full A5 completion claim follows from its source
or control-test results.
