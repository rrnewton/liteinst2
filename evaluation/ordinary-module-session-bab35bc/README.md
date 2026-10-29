The input-driven module client at bab35bcde867688d2b980627bc4e08c3bdef296b accepts bounded CSV records and
makes real CSV and length calls through two normally loaded functions. It reuses
the existing 10 ms controller, strict 2 ms arm gate, 2 s shutdown and three epoch
banks. Complete input bytes, raw journal, history and Report records remain
joined to each accepted call. Finalized input refusals stay nonzero and distinct
from hard clock, SDK or owner failures.

Seventeen new Rust controls pass in the exact-source workspace: four native
profile/accounting controls and thirteen input/consumer controls. Eighteen native
runner controls and thirteen streaming collector controls passed separately,
as did the original helper's strict C syntax/warnings check. Synthetic metadata
controls establish no actual native return or pending-owner transition.

All seven required checks passed. The default-parallel workspace reported
3,201 passes, zero failures and 36 ignores in
357.459 seconds; serial launch reported 1,039 passes.
Historical allocation and prefixed-pun checks also passed. Counts sum terminal
observations and may include nested child summaries. These durations describe
validation operations, not application performance.

The compact receipt retains both development failures, their corrections,
commands, exact source/review hashes and closed-log digests. Raw logs remain
ignored. This supports claim 4's systematic validation. Native K10/K1000 state
qualification, deterministic owner controls, the fixed-five release campaign,
accuracy, performance and full A5 remain pending. No sixth timing attempt or
relaxed deadline is introduced.

Reproduce on this revision:

```sh
python3 -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/module-session-new-checks" --checks-only
python3 -B evaluation/ordinary-module-native/controls.py -v
python3 -B evaluation/ordinary-module-session/controls.py -v
gcc -std=c11 -O2 -Wall -Wextra -Werror -fsyntax-only \
  evaluation/ordinary-module-session/original.c
```

The bounded workspace recipe preserves default libtest parallelism and records
the exact revision, commands and AMD EPYC Zen 5 dev host. These functional
checks claim no CPU reservation; release qualifications use separate receipts.
