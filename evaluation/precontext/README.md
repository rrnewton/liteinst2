# Optional observation before context capture

This qualification checks the constrained, unsafe pre-context core API. The entry gate reads a selector once and records Fast or Slow in caller-owned scratch; the return gate follows that same choice even when a helper changes the selector during the call. Fast bypasses context capture and the observer. Slow uses the existing preserving observer. Publication still requires quiescence; the selector is not a code-publication or epoch authority.

The fixed native population is two seeds, two branches and both initial selector values: eight original/candidate pairs with 148 full-state comparisons, plus two malformed-entry cases that must stop at the local UD2 before application execution. Each positive child physically returns and joins its real selector writer. The unchanged state comparator includes GPRs, defined flags, canonical XSAVE, application input and stack/red-zone bytes. Separate controls reject corrupt layouts, acknowledgement fields, trailing messages and missing return records.

Run from a clean checkout of the exact revision:

```sh
python3 -B evaluation/precontext/verify.py \
  --revision "$(git rev-parse HEAD)" \
  --raw "$PWD/ignored/NEW_RUN" \
  --toolchain "$TOOLCHAIN" --cargo-home "$CARGO_HOME"
```

`TOOLCHAIN` names a Rust toolchain directory; `CARGO_HOME` contains the already fetched dependencies. The recipe uses an offline release build, four available CPUs and four compiler jobs. Native execution has a 20-second CPU limit and 30-second wall limit; each pair shares its original 15-second deadline from setup through reap and each executor has a 20,000-step limit. Failures remain failures. Logs and captures stay under `ignored/`; `NEW_RUN/public` holds compact result and receipt JSON suitable for publication. Python corruption controls, six core tests, two compile-fail contracts, eight planner tests and thirteen inherited oracle calibrations are prerequisites.

This is functional qualification of a fixed core fixture. It does not establish frontend accounting, arbitrary function/ABI support, concurrent code publication, cheap-off latency, performance or a completed profiler. Command durations are operational metadata, not benchmark results. Recorded results will identify their exact tested revision and hardware.
