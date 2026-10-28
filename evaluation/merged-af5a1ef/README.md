All seven required checks passed at merge
`af5a1ef2af2b091f915c3c4ff2150781a644aac6`, including main `cc846a8`.
Workspace: 2,546 passed / 0 failed / 5 ignored, 322.030 s. Serial launch:
1,039 passed, 124.868 s. Five nested workspace summaries are excluded.
The receipt records commands, limits, hardware, runner/helper source hashes,
compiler version and clean closure with zero rescued descendants. Durations
are operational.

Reproduce on that clean revision:

```sh
python3 -B evaluation/admission/check_exec_identity.py --checks-only \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" --output "$REPO/ignored/NEW_GATES"
```

Export a closed run using its actual receipt hash and revision:

```sh
python3 -B summarize.py --closed "$CLOSED_GATES" --sha256 "$RECEIPT_SHA256" \
  --revision "$TESTED_REVISION" --output "$NEW_RECEIPT"
```

The [concurrent profiler](../concurrent-epochs-84d0040/README.md) and
[cleanup identity](../creation-identity-088dc0a/README.md) reports retain their
separate tested revisions and earlier failures. This successful merge run does
not establish the cause of the unresolved backing-child or orig_rax failures.
