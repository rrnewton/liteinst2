# Actual-PC cross-page fetch and wait custody

Tested source: `d3dc105f8bd939415852e6d19ca075e27db66a6c`.
The final qualification and both parallelism cohorts use this exact clean source,
with 1,483 tracked source files and source manifest SHA-256
`667ee698b0939364803fed471c28f722b5367fe2d8c5970a6ce35748aad02426`.
This report and the final receipts are later evidence-only additions. The
[previous runtime report](actual-pc-runtime-results.md) remains the historical
16-native-case, one-page qualification.

The two added runtime cases use an 8,192-byte original source VMA. Ordinary
`MOV RAX, imm64` begins at `0x400ffd` and genuinely fetches across two pages,
finishing at `0x401007`. Selected CPUID begins at `0x400fff` and finishes through
typed scripted emulation at `0x401001`, with both original pages remaining NX.
Both check the complete original source, full architectural state, exact map
projection, source/census/control identities, unexecuted successor marker and
physical cleanup. The ordinary case checks all six private calls and seven
actual waits. These extend the finite actual-PC profile; they do not establish
arbitrary program, loader, signal, thread or mapping support.

A separate Owner regression exercises a real seized group stop. Between the
actual `waitid(WNOWAIT)` peek and `waitpid(WNOHANG)` consume, an actual
`PTRACE_LISTEN` withdraws the stop's waitability without executing original user
instructions. The test retains and requires the native LISTEN result `0`,
immediately captured errno `0`, and actual consume result `0`. It checks that
the original process pin and exact owned identity remain, no stop or terminal
status is fabricated, and application and broker are physically reaped during
cleanup. Production now treats a zero consume as no event and retries through
the existing bounded owner path. Negative results and exact-TID consumption
checks retain their previous behavior. No wait result is substituted.

This evidence supports candidate claims **1** (page admission without modifying
executing original bytes), **2** (unprivileged interception from the first original
instruction within the stated profile), and **4** (explicit tactic and failure
validation). It supplies no preemption-clock result for claim **3**, no performance
claim, and no claim that those broader candidates are fully established.

## Reproduce

Use a clean checkout of the tested revision and the recorded compatible hardware
and toolchain. The extra cohorts use the installed `cpuset-alloc` command to
reserve eight CPUs; no `RUST_TEST_THREADS` override is passed to them.

```sh
python3 evaluation/admission/run.py --expect-revision d3dc105f8bd939415852e6d19ca075e27db66a6c
cpuset-alloc run --cores 8 --tag li2adm-d3dc-unit -- python3 evaluation/admission/default_parallel.py --expect-revision d3dc105f8bd939415852e6d19ca075e27db66a6c --cohort unit
cpuset-alloc run --cores 8 --tag li2adm-d3dc-fork -- python3 evaluation/admission/default_parallel.py --expect-revision d3dc105f8bd939415852e6d19ca075e27db66a6c --cohort fork
```

The six-command driver retains the exact recorder, formatting, strict Clippy,
workspace tests, all-features/all-targets check, and serial launch command arrays.
Its unchanged per-command limits are 180/180/180/360/180/180 seconds. It uses four
build jobs and four workspace test threads. Each extra cohort runs four times
with a 180-second limit per repetition and default libtest parallelism.
Incremental compilation is disabled and all commands use the one target tree.

Hardware: AMD EPYC 9D85, x86-64, family 26/model 17/stepping 0, microcode
`0xb101066`; 316 visible logical CPUs. Linux upstream version `7.1.3` with full
release hash in each JSON receipt. Rust `1.97.1` (`8bab26f4f`, 2026-07-14) and
Cargo `1.97.1` (`c980f4866`, 2026-06-30). The invoker was non-root with zero
effective capabilities. The six-command run observed affinity 316; each extra
cohort observed affinity eight. The receipts retain complete typed hardware,
command, toolchain, configuration, resource, source and cleanup metadata without
host paths or raw captured logs.

## Final observations

| Command/cohort | Outcome | Elapsed seconds |
| --- | --- | ---: |
| Recorder | 273 passed | 17.252 |
| Format | Passed | 3.971 |
| Strict workspace Clippy | Passed | 20.642 |
| Workspace tests | 1,866 passed, four unchanged ignores, 89 harnesses | 345.585 |
| All-features/all-targets check | Passed | 11.495 |
| Serial launch | 786 passed, 27 harnesses | 94.724 |
| Default-parallel launcher units | 494 passed in each of four repetitions | 4.175 / 4.185 / 4.208 / 4.174 |
| Default-parallel fork cohort | Seven passed in each of four repetitions | 0.278 / 0.268 / 0.270 / 0.263 |

The serial receipt requires all 75 exact named native identities: the previous
74 plus the wait-custody case. Runtime remains 138 methods, comprising 120 pure
controls and 18 native cases. The existing 50 static native cases, 15 dynamic
fixtures, 388 matrix invocations, and separately typed cleanup-helper controls
remain required. These are case/invocation counts, not independent instruction
samples or a probabilistic reliability estimate. All 14 final command cleanups
completed, with zero adopted descendants reaped by the outer recorder.

| Receipt | SHA-256 |
| --- | --- |
| [Six commands](results/20261026T191823.612716Z-d3dc105f8bd9.json) | `2aa1797653610f6d4aad6de17055d110913ec7e9ccf231d9c90a27ef8278db0c` |
| [Four unit repetitions](results/20261026T192649.741364Z-default-parallel-d3dc105f8bd9.json) | `c97fd4d6acb46d10f5fefba997e9f817df60f09ee917bc7b21c879b3e283e095` |
| [Four fork repetitions](results/20261026T192731.000494Z-default-parallel-fork-d3dc105f8bd9.json) | `c276b2934c11031d4aa5dd52779d74a23164aabd1c4c54a38abcff2ed52ccbd3` |

## Preserved earlier failure

Cross-page source `1604d53a32aaac05181e61479258e36a39ce2137` passed the full
[six-command run](results/20261026T185509.603378Z-1604d53a32aa.json), SHA-256
`7a5ecac098634dbc0ad2785a9e8b14c8a5ac4b78dbb7d3b32a241cc6d5e27b44`.
The following [default-parallel run](results/20261026T190329.994590Z-default-parallel-1604d53a32aa.json), SHA-256
`4e0eee6352ebd8e82ee00d045b8567b1444addcfbaf0d1977f4f62c179d8a1a4`,
passed three repetitions of 493 cases, then failed the fourth with 492 passes
and one failure in
`linux::remote::dynamic::owner::tests::unexpected_newborn_is_reaped_without_public_creation_support`.
Cleanup reported lost wait ownership. All 18 runtime native cases passed in
that repetition, and the outer recorder's cleanup completed with zero adoptees.
No fork cohort was run at that earlier source. Both receipts were committed
unchanged in `d1e22156fba677ca036c106ca3982f3ea67304cb` before the correction.

Inspection found the real nonblocking-consume defect described above. The new
native regression deterministically exercises that defect, but the earlier
failure did not record the relevant wait result; its exact cause remains
unproven. Passing later repetitions do not relabel it or prove universal absence
of races. The old failing test's complete body and deadline remain unchanged.
All old native names, pure test identities, comparison rules and limits remain;
the recorder gains eight controls for exact inventory, malformed/missing/failed
results, harness identity and privacy. Raw logs remain private and their hashes
are retained in the public JSON summaries.
