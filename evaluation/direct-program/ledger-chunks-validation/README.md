# Compact-ledger correctness

Revision `fd50d5ef02fd042fa4282cb83224d1b60900723c` passed full Rust/Python correctness validation on an AMD EPYC Zen 5 dev host: **4,687 top-level + 11 nested = 4,698 raw workspace passes, zero failures, 43 unchanged ignores**. Serial launch: **1,039 passed**, zero failures or ignores.

All prior cases remain, with twelve Rust and four Python additions. All **60 dedicated focused controls** passed in this full run; their Rust cases overlap workspace counts. All owners closed cleanly with zero rescues.

Earlier attempts remain **FAILED**: focused-v1 had a quoted-error assertion mismatch; checks-v1 stopped at strict Clippy; checks-v2 had one launch setup timeout then `Disconnected`, with serial unobserved. The test-only correction starts the same 3-second launch/admission deadline after mutex acquisition. Lock wait was not measured; no causal diagnosis is claimed.

[receipt.json](receipt.json) records commands, census, source, resources and failures; timings are validation costs, not benchmarks. The separate freestanding decoder and corpus campaigns are outside this report; no broad native, complete-CFG, runtime-exemption or performance qualification follows. Prior [upstream corpus failures](../grouped-upstream-result/README.md) remain unchanged.

Use a clean checkout of the exact revision. Set `CPUSET_ALLOC`, `TOOLCHAIN` and an unused directory under `ignored/` as `OUTPUT`:

```sh
AGENT_UTILS_ENGINE=python "$CPUSET_ALLOC" run --cores 12 --tag li2core-ledger-chunks-full -- /usr/bin/python3.9 -I -B evaluation/direct-program/validate_ledger_chunks.py --revision fd50d5ef02fd042fa4282cb83224d1b60900723c --output "$OUTPUT" --toolchain "$TOOLCHAIN"
```

Reserve 12 CPUs externally; the runner sets jobs/threads and retains the existing storage and native bounds. `--focused` needs a fresh output and does not replace full validation.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
