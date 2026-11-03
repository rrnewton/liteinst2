# Freestanding decoder facts

Revision `fd50d5ef02fd042fa4282cb83224d1b60900723c` passed **15 decoder/descriptor/model subjects and 138 reader controls** on an AMD EPYC Zen 5 dev host. The separate `facts-v2` attempt took 264.833 seconds on one reserved CPU; this is validation cost, not a benchmark.

[receipt.json](receipt.json) retains every numeric subject result. Five intentional fatal-path children exited 125; their bounded helpers exited 1 as required. The other 111 inner owners exited 0. All 116 inner owners and the outer owner closed normally with complete cleanup and zero rescues.

The earlier `facts-v1` remains **FAILED** at the 320 MiB copy/link reserve: eight subjects and 68 reader controls passed; seven subjects were unobserved. Lossless storage reclamation preceded the second attempt. Source, cases, comparisons, subprocess bounds, reserve and slot ceilings stayed unchanged.

Coverage is finite shared decoder/GPR-fact merge correctness. The marked scalar-region test-export build is separate from production archives. Span/MOV/ADD descriptor/model checks do not execute generated instructions. No broad native, complete-CFG, runtime-exemption or performance qualification follows. Raw results remain private; the receipt binds CLOSED metadata.

Use a clean checkout of the exact revision. Set `PYTHON` to Python 3.11+, `TOOLCHAIN` to the recorded Rust toolchain directory, `CPUSET_ALLOC` to the CPU reservation tool, and `OUTPUT` to an unused path under `ignored/` with a fresh basename:

```sh
AGENT_UTILS_ENGINE=python "$CPUSET_ALLOC" run --cores 1 --tag li2core-freestanding-facts -- "$PYTHON" -I -B evaluation/shared-x86/validate_decoder_facts.py --revision fd50d5ef02fd042fa4282cb83224d1b60900723c --output "$OUTPUT" --toolchain "$TOOLCHAIN"
```

The [validator](../validate_decoder_facts.py) constructs all build/link/subject commands. The receipt records versions, source hashes, offline Cargo settings, unchanged subprocess bounds and storage ceilings. Each attempt needs a fresh output.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
