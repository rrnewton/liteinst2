# Optional fast memset primitive

Run the committed evaluator on one externally reserved CPU:

```
PYTHONDONTWRITEBYTECODE=1 python3 evaluation/inprocess/page_selected_fast_memset.py \
  --expect-revision <full-40-character-commit>
```

The evaluator compiles the actual `tools/page-entry/bridge.c` twice. The scalar
object has no fast macro; only the fast object gets `LI2_FAST_MEMSET=1`.
Production build scripts remain unchanged and continue to select scalar
memset. No Rust archive or decoder build is used for this C primitive oracle.

Each functional command checks 273 cases, comparing every accessible buffer
byte and retaining exact whole before/after hashes. Lengths include zero,
unaligned ranges, page boundaries and the actual complete chain-slot size.
Fills include zero, nonzero, negative and byte-truncated values. Genuine guard
pages surround every buffer; the zero-length cases include NULL and a pointer
into a protected page. Return-pointer and live DF checks remain mandatory.

Both functional lanes must pass before measurement. Four subsequent processes
run scalar/fast, then fast/scalar, with all 273 functional checks repeated.
Each records eight strictly positive CLOCK_MONOTONIC_RAW intervals of 256
whole-slot fills alternating between two buffers. All 32 raw intervals are
published; no minimum-time selection or speed threshold is used. These are
warm helper-call batches including loop/call overhead, not isolated reset
latency or real-program timings. Each native command retains the unchanged
5-CPU-second, 512-MiB, 16-MiB-file and 15-second wall bounds.

Before target execution, actual compiler `-M` output binds lexical and resolved
headers for all four preprocessing paths. The evaluator retains tools and C
link inputs, both bridge objects and executables, actual hosted dependencies,
DWARF slot/row/record sizes, and full emitted memset bytes. The fast body reader
checks one exact CLD/REP STOSB with actual AL/RDI/RCX custody, original-pointer
return and untouched callee-saved registers. The scalar reader requires its
actual byte-store loop. Missing DWARF, unexpected emitted code, build failure,
nonzero exit, cleanup failure or any changed input/artifact fails qualification.
Partial build outputs and captures remain private; no failure is reclassified.

`check.py` is also an offline exact record parser. Its `--slot-bytes` input must
be established independently from both actual binaries' DWARF. `layout.py`
only reads debugger metadata; it never starts an inferior. `build-oracle.sh`
builds but never runs the binaries.

The unchanged owner/TRACE/register/REP/rseq full-state suites are separate
requirements before enabling this implementation in any production profile.
In particular, application DF=1 must survive genuine signal entry/return even
though the trusted runtime C ABI uses live DF=0. No FP/state comparator or full
slot reset is reduced by this primitive change.
