# Profiling unchanged FreeBSD strnlen with short returns

Revision `f547c199ef01d40ed341657be5c5aaf0ec3adf0e` adds complete-function
planning and profiling for a bounded scalar function whose return blocks are too
short for separate five-byte patches. The new planner keeps the complete closed
control-flow graph in one image and retains entry and every return observation.
The previous block planner and its short-return refusal remain unchanged.

The subject is the byte-exact FreeBSD 14.1 `lib/libc/string/strnlen.c`, including
its original license, from commit
`10e31f0946d820d53adc58b7d013b969e4a9a8ed`. The recipe compiles that translation
unit with the existing C flags, authenticates all 16 source/header inputs and
the preprocessed body and LP64 ABI, then localizes and strips the object before
making a separate candidate copy. The resulting function has 41 bytes, 13
reachable instruction heads, 14 directed edges and two one-byte return sites at
offsets 34 and 40. The compiler's bytes, including its NOP padding and both returns, were kept intact.

The first complete release attempt passed on an **AMD EPYC Zen 5 dev host** with
Rust 1.97.1 and GCC 11.5.0. Qualification took 96 seconds, an operational wall
duration rather than a throughput measurement.

| Population | Result |
| --- | --- |
| Original/instrumented state | 16 pairs, 32 children, 1,668 full-state comparisons, 0 mismatches |
| Input reads | 284 architectural one-byte reads checked against the actual bounds; zero reads for zero-bound cases |
| Reachable coverage | Complete head, edge and return union for each of two seeds |
| Functional consumer | 8 original and 8 installed calls; all scalars and guarded inputs match |
| Installed ownership | 4 sampled, 3 closed, 1 removed; two generations |
| Complete accounting | 16 events, 4 actions, all 512 journal words, two Reports with 2 records each, actual worker join |
| Preload refusals | 3 expected refusals, 0 subject calls |
| New release controls | 7 core, 6 frontend, 6 state, 7 consumer, 8 provenance and 9 parser methods; 0 failures |
| Fresh existing prerequisites | Named and stripped checksum cases each retain 4 pairs/978 comparisons and 8 original/8 installed calls; named short-return refusal retained |

Eight cases per seed preserve bounds 0, 1, 1, 2, 17, 64, 64 and 64, including
empty, early-NUL, final-NUL and no-NUL inputs. State checks retain full registers,
defined flags, XSAVE, protected stack, data and source/image bytes through the
actual outer return. Each pair retains its original absolute 15-second deadline
and continuous 20,000-step bound. All 46 bounded helpers and 48 parent owners
completed normally with ECHILD and no rescues; the whole-recipe owner also closed
normally. CSV rows summarize checks performed by the native producers; they do
not independently replay full state, journals or Reports.

This supports **claim 4: systematic validation** and establishes one unchanged
production translation unit in a controlled DSO. The current whole-function
profile requires a complete 5–80-byte scalar, read-only, closed function and
caller-supplied entry/lifetime guarantees. It does not establish deployed-libc
coverage, arbitrary application discovery or full A5 completion. Callback ticks
are uncalibrated observations, not profiler accuracy or overhead measurements.

Reproduce from the recorded revision with a fresh absolute `$RAW` under the
checkout's `ignored/` directory:

```sh
$PYTHON -B tools/rapid-profiler/verify_strnlen_interval.py \
  --revision f547c199ef01d40ed341657be5c5aaf0ec3adf0e \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

`receipt.json` contains exact normalized commands, revision, tool/source/artifact
hashes, hardware and closure summaries. All compact state, accounting and refusal
CSV rows are retained, including both fresh prerequisites. Raw compiler text,
header manifests, environments and logs remain ignored.

The seven hand-back checks also passed at this exact source revision. Default
workspace parallelism used all 316 available CPUs without a test-thread override:
**2,935 passed, 0 failed, 33 ignored** (359.5 seconds). All seven historical
exec-admission/allocation failure cases were present and passed. Serial launch
passed 1,039 tests; focused staged-allocation and prefixed-pun suites passed 3
and 36. Formatting, strict workspace Clippy and all-target compilation passed.
`workspace-checks.json` records the commands, bounds and closure results.

Reproduce those checks at the recorded revision with:

```sh
$PYTHON -B evaluation/admission/check_exec_identity.py \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME" \
  --output "$REPO/ignored/NEW_GATES" --checks-only
```
