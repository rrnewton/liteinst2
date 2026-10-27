# Ordinary shared-library interval client

The combined native-state and functional run passed at
`ff18353d4ed70bb3ad4018079328833bac4696b4` on the owner-labelled
**AMD EPYC Zen 5 dev host**. The observed CPU fields are AMD family 26,
model 17, stepping 0, x86-64; the label is separate from those observations.
All seven required final gates passed at that revision. The workspace had
**2,506 passed, zero failed, four ignored** in 336.16 seconds; five nested child
summaries are excluded from that total. Serial launch passed in 131.68 seconds,
as did all three historical allocation regressions. See [validation.json](validation.json).
These are operational validation durations, not performance measurements.

The normally loaded, independently trusted shared library contains the scalar
`ordinary_checksum_nonempty` function. Its real compiler output is instrumented
at entry and every reachable return. The empty-capable alternative has a
one-byte return block and is a required whole-factory refusal, with no padding
or omitted return site.

| Required observation | Result |
| --- | ---: |
| Native state pairs: two seeds × lengths 1 and 64 | 4 PASS |
| Live state comparisons | 978 |
| Native children / real outer returns | 8 / 8 |
| Native mandatory short-return refusal | 1 |
| Original / instrumented functional calls | 8 / 8 |
| Instrumented entries / returns | 8 / 8 |
| Retained completions / unsampled calls | 6 / 2 |
| Completion reports before / after rearm | 4 / 2 |
| Raw interval rows | 8 |

Every functional value matched both the original call and the independent
Rust model. The 96-byte guarded input remained unchanged and the worker joined
before input release. Both execution stages closed with exit 0, strict ECHILD,
unchanged helper inputs, no unexpected descendants and no cleanup events or
errors. These joins and the exact build/source/tool hashes are in
[receipt.json](receipt.json).

[state-pairs.csv](state-pairs.csv) and [intervals.csv](intervals.csv) retain the
original numeric CSV bytes. The state totals come from the live comparator,
not a separate saved-capture replay. Qualification runs through the real
library CALL/RET and gate post-POP boundary, with the inherited GPR, flags,
canonical XSAVE, data and exact `[S-128, stack_end)` stack comparisons. Each
child then restores only its own saved Rust harness context and executes the
real outer return. This is not whole-64-KiB stack or arbitrary-function
qualification.

The Rust executables used **release opt3**, debug information 0, with debug
assertions and overflow checks enabled. The shared library used GCC 11.5.0
`-O2`; the complete flags and both Cargo artifact profiles/cache statuses are
recorded. Endpoint values are raw fenced RDTSCP observations at the callbacks.
Their differences include instrumentation and descheduling: they are
**uncalibrated TSC ticks**, not nanoseconds, timing-accuracy evidence, throughput
or an overhead comparison.

## Reproduce

Use a clean checkout at the exact revision above, with the locked dependencies
already available offline. Set `REPO`, `TOOLCHAIN`, `USER_HOME`, and `CARGO_HOME`
to canonical absolute directories; `TOOLCHAIN` is the installed Rust 1.97.1
directory. `PYTHON` names the tested Python 3.12, and `CPUS` names four available
CPU IDs. Both output directories must be new. Run the commands sequentially
with no competing source or target writer; they share the single `REPO/target`.

```sh
REVISION=ff18353d4ed70bb3ad4018079328833bac4696b4
env -u PYTHONOPTIMIZE "$PYTHON" -B "$REPO/tools/rapid-profiler/verify_ordinary_interval.py" \
  --revision "$REVISION" --raw "$REPO/ignored/ordinary-reproduce-new" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"

env -u PYTHONOPTIMIZE "$PYTHON" -B "$REPO/tools/rapid-profiler/validate_ordinary.py" \
  --repo "$REPO" --revision "$REVISION" --output "$REPO/ignored/ordinary-gates-new" \
  --toolchain "$TOOLCHAIN" --user-home "$USER_HOME" --cargo-home "$CARGO_HOME" \
  --cpus "$CPUS"
```

The first script builds the trusted DSO, makes a distinct candidate copy, builds
both release executables, requires all four state pairs, then runs the complete
functional client. It selects four available CPUs for building/state checks and
one for the functional worker. The native child deadline is 15 seconds including
setup; its continuous 20,000-step allowance starts at readiness. Original owner
validation and candidate publication/attachment precede readiness. This is an
explicit accounting boundary, not evidence that the earlier single-stepped
preflight fit that allowance.

The second script runs the seven final validation commands: format, strict
workspace Clippy, workspace check, workspace tests, the entire serial launch
package, staged-allocation tests and the prefixed-pun target. Its development/test
profile is opt0/debug0 with assertions and overflow checks enabled. Individual
walls remain 180 seconds, except workspace tests at 360 seconds. Nested libtest
terminals are recorded separately and are not summed into a unique-test count.
The first attempt timed out at 360 seconds after 33.58 seconds of compilation.
The identical command passed on retry using the built binaries. The failed
attempt and its cleanup record remain in the validation receipt.

## Retained failures and boundaries

[failures.csv](failures.csv) preserves all seven earlier attempts as **FAILED**:
the initial ELF-format rejection, planning refusal, two step-budget
failures, two outer-return validation failures, and the functional stack-headroom
failure. The diagnostic retry identified ptrace TF remaining after the outer
return. V6's four state pairs and 978 comparisons passed, but its functional
stage failed; it is not a combined pass. Blank historical state counts mean no
completed cohort count was reported, not that no instructions ran. Exact
revisions, source-reproducer references and private-record hashes are retained;
raw logs, addresses, binaries and captures are not published.

The supported contract remains a trusted, bounded integer leaf with read-only
input and complete external-entry closure. Calls within the leaf, indirect
control flow, active CET, unwind, signals/nonlocal exits, fork, unload and
concurrent source mutation are outside this profile. Installed code and its
owners stay alive until process exit. This is a functional client and bounded
state qualification, not full A4/A5 completion or general ABI coverage.
