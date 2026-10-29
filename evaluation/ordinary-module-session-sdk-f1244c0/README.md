Two sealed normal leaf functions can now share reusable streaming sessions at
f1244c0381bc8c4b6e201572e39ec0d5eb34c689. The exact profiles have K=10 or K=1000 per
function, three prepared epoch banks, one caller/in-flight slot, and absolute
history. Bank reclamation, function-tagged transfers and complete history use
the existing receipt/ownership paths. Finite-profile guards remain intact.

All 14 new SDK controls pass in the exact-source workspace. They cover profile
isolation, allocation/refusal atomicity, the same returned bank/epoch, independent
function budgets, saved closed owners across rearming, all 512 journal words,
and history beyond 512 actions. These are production-helper controls with
synthetic immutable site metadata; native execution of this streaming profile
is a separate qualification.

All seven checks passed. Default-parallel workspace reported
3,184 passes, 0 failures and 36 ignores in 349.203 seconds;
serial launch reported 1,039 passes. Historical staged-allocation and
prefixed-pun checks passed as well, alongside fmt, strict Clippy and all-target,
all-feature check. Counts sum terminal observations and can include nested child
summaries. Seconds are operational durations, not performance measurements.

The receipt retains the two development failures, their fixes, every command,
source/review hashes and closed-log digests. No assertion, comparator, tolerance
or existing case was weakened. Raw logs stay ignored. This supports claim 4's
systematic validation; native streaming, strict scheduling, accuracy, performance
and full A5 remain open.

Reproduce on the recorded revision using the existing bounded script:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/module-session-sdk-new-run" --checks-only
```

The script keeps libtest's default parallelism and records the AMD EPYC Zen 5
dev host identity, exact revision and commands. No CPU reservation is claimed
for these functional checks. Timed release qualifications remain separate.
