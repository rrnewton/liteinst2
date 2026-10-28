# Native hardware-stop prerequisite

The batch oracle uses a private Linux x86-64 execution breakpoint to reach fixed
instruction boundaries. It saves DR0/DR6/DR7, refuses any active debug owner,
installs only local execution slot zero, authenticates the exact hardware trap,
and restores all three saved words with readback before returning. Existing
wait, step, cleanup, state comparators and debugger flag masks remain unchanged.

```sh
python3 -B tools/rapid-profiler/tree-work/verify_hardware_stop.py \
  --revision "$REVISION" --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

The runner requires a clean tracked checkout at the full revision and builds
release code with optimization level 3, debug information off, assertions and
overflow checks on. It runs the parser controls, eight pure Rust controls and
one exact native test in a fresh process. The native control has one absolute
15-second deadline preceding mappings/fork and one continuous explicit-step
counter capped at 20,000. Its outer process has 10 CPU seconds, 15 wall seconds
and 1 MiB output. Every stage requires normal exit, ECHILD and zero cleanup
rescues; a failure remains a failed attempt, with no fallback or retry.

The positive fixture takes two authenticated hardware stops, single-steps two
actual NOPs with debug state restored, and exits normally. It compares every
register field, canonical XSAVE and complete code/data/stack mappings. Only the
hardware-owned RF bit may differ at a stop; only debugger TF may differ after
SINGLESTEP. It reports whether RF was actually exposed and requires RF clear
after each step. The next CONT must reach a new hardware event, with no stale
single-step cause. This tests the stop/restore/step/stop sequence on the actual
kernel; it supplies no SDK result or performance number.

The broader calibration target retains all 82 inherited tests and adds eight
pure controls. The new native prerequisite is its only newly ignored test and
is qualified separately by this runner. No inherited test becomes ignored.

`result.json` records the exact revision, hardware, commands, tool/artifact
hashes, source-manifest digest and measured counts. Detailed source manifests,
requests, logs and binaries stay under `ignored/`. A summarized receipt can be
copied to `evaluation/`; no host paths or names belong in the public record.

For the subsequent batch route, calls 1 and 8 receive full state comparison;
calls 2–7 receive physical-transfer and functional checks. After every actual
middle CALL/RET step, that route must independently require RF clear. This
NOP control alone does not establish CALL/RET behavior or batch qualification.
