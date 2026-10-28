# Hardware-stop prerequisite

The first release attempt passed at source revision
`6ed17770717db70c1c08820349a6da82cbad94a8` on the AMD EPYC Zen 5 dev host
(AuthenticAMD family 26, model 17, stepping 0). This supports claim 4 only as
qualification of the private oracle breakpoint mechanism.

| Observed result | Count |
| --- | ---: |
| Pure Rust controls passed | 8 |
| Native children normally exited and reaped | 1 |
| Authenticated hardware stops with RF exposed | 2 |
| Actual NOP SINGLESTEP operations, RF clear afterward | 2 |
| Stops or steps exposing TF | 0 |
| Cleanup rescues across all four stages | 0 |

At each stop, DR0/DR6/DR7 exactly matched their saved values after restoration.
All 27 register fields, canonical XSAVE and complete code/data/stack mappings
met the control's unchanged-state predicates. The control permits only the
owned RF effect at a hardware stop and debugger TF exposure after SINGLESTEP;
TF was not exposed in this run. The final exit was zero and exact-child ECHILD
was observed. Four parser methods also passed, including optimized-interpreter
refusals and malformed population/count controls.

```sh
python3 -B tools/rapid-profiler/tree-work/verify_hardware_stop.py \
  --revision 6ed17770717db70c1c08820349a6da82cbad94a8 \
  --raw "$RAW" --toolchain "$TOOLCHAIN" \
  --user-home "$USER_HOME" --cargo-home "$CARGO_HOME"
```

Use a new `$RAW` beneath the checkout's `ignored/` directory. The runner requires
a clean tracked checkout and canonical absolute local paths for the toolchain,
user home and Cargo home. Rust 1.97.1 built optimization level 3, debug info off,
assertions and overflow checks on, with four build jobs. The receipt records
exact tool/artifact hashes and the digest of 343 source inputs. Root also joined
every source input back to the recorded Git revision and checked all four
closed stage receipts and streams. The source manifest, command logs and raw
process receipts stay ignored.

The native test retains one absolute 15-second deadline from before allocation
and one continuous 20,000 explicit-step ceiling. The outer subject bound is
10 CPU seconds, 15 wall seconds and 1 MiB output. All stages completed normally,
with ECHILD and zero unexpected descendants or cleanup events. Operational
stage durations in `result.json` are not performance measurements.

This is a two-NOP mechanism prerequisite. It supplies no SDK batch equivalence,
CALL/RET RF-retirement, full-middle-call state, application performance or timing
accuracy claim. The batch route still needs its actual transfer successor checks
and selected full-state comparisons.
