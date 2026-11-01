# Bounded fused-loop component

This independent component uses the real decoder, planner, emitter, unchanged
DIRECT/MOV byte models and the version11 typed recovery entry points. It
executes no emitted instructions and grants no owner or performance credit.
The previous bounded-block component and its requirements remain unchanged.

Run on one externally reserved CPU from the exact clean source revision:

```sh
python3 -B evaluation/inprocess/bounded_fusion_component/run.py \
  --expect-revision REVISION --archive DECODER_ARCHIVE \
  --archive-sha256 ARCHIVE_SHA256 --cpu RESERVED_CPU \
  --output target/evaluation/inprocess/FRESH_ATTEMPT
```

The supplied static archive is bound by its complete bytes and SHA-256; this
runner does not claim to build it or prove its source provenance. The native
owner experiment separately requires a freshly built decoder and its complete
prerequisites. Build and execution retain the bounded-block runner's original
30/5 CPU-second and 60/15 wall-second limits, 512MiB memory and 16MiB captures.
The compiler uses -O2. The receipt records exact source, hardware, command,
compiler dependencies, artifacts, outcomes and cleanup. The summary contains
only portable facts and hashes; publish it only after inspecting the receipt.

The fixed population is 14 accepted plans, 10 refused plans, 14 corruptions,
60 old-policy checks, 1,536 DIRECT models, 1,280 MOV models and 56 copied-state
boundaries. For every independent model step the C oracle requires both typed
recoveries to match; it also checks every generated-slot interior byte. Their
observed counters are recorded separately from these fixed populations.
Neither a component pass nor these counts substitutes for native cold/warm
execution, actual store-fault and guard-rejection recovery, or completed
real-program measurements.

Two one-line wrapper translation units give the unchanged DIRECT and MOV
models distinct compiler output names. The actual compiler include closure
must contain both complete original models and headers; all nine translation
units retain separate preprocessed, assembly, object and stack-usage files.
