# Shared x86 decoder regression

Source `7be445a56a42ef0544a8f0f59021fa39b39267e6` consolidates decoder setup,
selected instruction classification and GPR/width facts in `liteinst-x86`.
Offline scanning, runtime admission, launch and in-process selected semantics,
and the freestanding page decoder consume that leaf. Adapter-specific refusal
rules remain separate. Complete CFG/planner/encoder consolidation is still in
progress; [the exemption design](../../A3-SHARED-ADMISSION.md) is not implemented.

The single declared correctness campaign **FAILED** its unchanged 180-second
serial launch deadline. It is not a landing-ready result. No automatic retry
was performed. Hardware: **AMD EPYC Zen 5 dev host**, Rust/Cargo 1.97.1,
GCC 11.5.0. [receipt.json](receipt.json) records the exact source/tree, commands,
CPU reservation, load, limits and results; [results.csv](results.csv) contains
the numeric outcomes. Raw logs and binaries remain private under `ignored/`.

| Check | Result |
| --- | --- |
| Formatting, strict Clippy, all-feature/all-target check | PASS |
| Parallel workspace, 12 build jobs and 12 harness threads | 4,586 raw passes: 4,575 top-level plus 11 nested; 43 unchanged ignores; 971.122 seconds |
| Serial launch, unchanged 180-second limit | FAILED timeout at 180.191 seconds; 817 observed passes, one unfinished test, 221 not started |
| Freestanding default and extended builds | PASS |
| Four decoder controls per build | Eight PASS, including expected exit 125 for tiny-arena and personality refusals |

The prior workspace roster is retained exactly, with three additive decoder
tests. All 27 critical regression cases and all 21 short-neighbor cases pass.
Serial cleanup completed, reaping two descendants; that does not turn its
partial run into a pass. Its one-minute host load rose from 304.07 to 364.33.
Elapsed times describe validation operations, not application performance.

Each decoder profile checks all 112 selected forms, the exact fatal reasons
102 and 106, and the freestanding seven-class/4,110-start result. The unchanged
reader also runs 34 negative controls per profile. These are ordinary decoder
regressions; they do not replace the separate complete freestanding dependency,
ELF or page-admission qualifications.

Reproduce from a clean checkout of the source revision, with dependencies
already available offline and a fresh output directory. `TOOLCHAIN` denotes
the Rust 1.97.1 toolchain directory. Reserve 12 disjoint CPUs with `cpuset-alloc`
(or an equivalent reservation and affinity wrapper):

```sh
cpuset-alloc run --cores 12 --tag shared-x86-reproduce -- \
  python3.9 -I -B evaluation/shared-x86/validate.py \
  --revision 7be445a56a42ef0544a8f0f59021fa39b39267e6 \
  --output ignored/shared-x86-reproduce \
  --toolchain "$TOOLCHAIN"
```

The runner owns bounded children, closes ownership records before reading
captures, checks source identity and cumulative storage limits, and records
failures and unobserved stages. It uses one nonincremental target with dev/test
debug information disabled. The extended decoder feature list is
`linked-epoch,mov-guard,add-guard`; builds and fixture executions use one CPU
inside the reservation. Inspect the final `closed.json` before its captures.
No performance or runtime page-exemption claim is made.

A4 / claim 4 remains open against the strict 20,000-step profile; an 80,000-step pass does not complete it.
