# Long-T3 complete workspace validation

The five required commands passed at `701c4c87e80efcb287a37c57c5b1d7ce5aecee0c`: **4,268 workspace passes, zero failures, 39 ignored**, plus **1,039 serial-launch passes**. Formatting, strict workspace Clippy and all-feature/all-target checking also passed. All prior test identities, outcomes and ignore reasons remain; the only additions are the four long-T3 ownership controls.

The workspace command took 749.59 seconds within its unchanged 900-second limit. The full owner took 938.28 seconds within 1,200 seconds; every owner closed normally with zero rescued descendants. Twelve reserved CPUs, twelve Cargo jobs and twelve harness threads were used; serial launch used one harness thread.

The separate [focused neighbor oracle timeout](../full-program-long-t3-result-v1/) remains a failed 180-second attempt. Its tests also appear in this complete passing workspace. These are distinct invocations; the full gate does not rewrite the timeout.

[receipt.json](receipt.json) records exact commands, revision, CPUs, loads, elapsed times and log hashes. Reproduce using the [prior bounded wrapper](../full-program-gnu-full-validation/) and [unchanged validator](../short-neighbor-parallel/validate.py), retaining receipts outside the checkout and substituting this revision plus a fresh output directory. The nine environment overrides and all command/owner bounds are unchanged. This validates correctness of the workspace; it does not qualify full-program artifact execution or performance.
