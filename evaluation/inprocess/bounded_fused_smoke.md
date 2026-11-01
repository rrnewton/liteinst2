# Fresh bounded-fused diagnostic

Run from an exact clean committed checkout, on one externally reserved CPU:

```sh
python3 -B evaluation/inprocess/bounded_fused_smoke.py \
  --expect-revision "$REVISION" \
  --expect-decoder-sha256 "$DECODER_SHA256" \
  --cpu "$RESERVED_CPU" \
  --output target/evaluation/inprocess/pf-fresh-smoke-1
```

`REVISION` is the full commit SHA. `DECODER_SHA256` is the independently
specified expected decoder archive SHA256. The unchanged builder builds that
archive from the current authenticated source and refuses an identity mismatch.
The output must be a fresh direct child of `target/evaluation/inprocess`.

This runs 94 fixed commands: the existing fresh decoder and application builds,
both maintained and differential capture builds, complete compiler dependency,
ELF/provider, full-byte oracle and DWARF checks, followed by the two original
mode-zero gated subjects. Each subject retains its original expected exit zero,
30 CPU seconds, 60 wall seconds, 512 MiB address-space and 16 MiB output limits.
All other command bounds are reused unchanged. There are no retries. Both
independent subjects are attempted after successful builds, including when the
first subject fails; any failure makes the receipt fail.

The receipt retains actual command arguments, durations, stdout/stderr, owner
records, source/tool/import/header facts, fresh build artifacts, namespace
preparation and final source/input/descriptor closure. Durations are diagnostic
only. Raw captures are retained on failure; they are not rewritten or accepted
as successful state evidence.

`observed_smoke_exit_zero` means both expected-zero subjects exited zero and the
diagnostic custody checks closed. It does not establish full native-state
equality, correctness qualification or performance. Native references, semantic
readers, seed and corruption-control cohorts remain in the unchanged full
`bounded_fused_owner.py` qualification experiment. This command is a fresh run,
not a byte-identical replay of any historical private smoke or failed receipt.
