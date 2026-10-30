# Merged scalar-span qualification — claims 1, 2 and 4

ADDS: opt-in cached execution of 131 scalar no-write instruction forms, including RIP-relative loads, entered through a genuinely closed TRACE predecessor. The finite native tests cover exact architectural state, generated read faults, ordinary resumption and a nested-signal refusal. This is bounded span execution; whole-process performance remains unqualified.

The tested revision is `7131fede6cac146981b3e1ba039f5edcc55149d2`, including main `0fb574bdf0e5c7c48700165535f5c2dd5da39ead`. The subsequent evidence commit adds only this report and numerical receipts. All runs used an unprivileged AMD EPYC 9D85 158-Core Processor, microcode `0xb101066`, Linux `7.1.3`, and stable Rust/Cargo `1.97.1`. The receipts retain the exact command, source and artifact identities, hardware, environment, bounds and cleanup result.

[Required-check receipt](20261030T181329.649943Z-checks-7131fede6cac.json), reserved CPUs 1, 16, 23 and 25:

| Check | Result | Seconds |
| --- | --- | ---: |
| Recorder | 357 passed | 116.796 |
| Formatting | passed | 8.892 |
| Clippy, all targets/features, warnings denied | passed | 45.488 |
| Workspace tests | 3,824 passed; 37 ignored; 0 failed; 106 harnesses | 709.457 |
| Compilation, all targets/features | passed | 30.810 |
| Serial launch | 1,039 passed; 0 failed; 27 harnesses | 138.227 |

Reproduce with `python3 evaluation/inprocess/checks.py --expect-revision 7131fede6cac146981b3e1ba039f5edcc55149d2` in the recorded toolchain and environment, on four reserved CPUs. The original 180-second recorder/serial limits and 900-second workspace limit are unchanged.

Two separate release-built native profiles then ran sequentially on reserved CPU 3:

- [Component JSON](20261030T183120.397570Z-scalar-span-component-7131fede6cac.json) / [CSV](20261030T183120.397570Z-scalar-span-component-7131fede6cac.csv): all 59 subjects qualified, comprising one metadata oracle and 58 hardware original/generated comparisons (56 completed paths and two required read faults). The 3,022 malformed-reader controls are separate from native credit.
- [Finite TRACE JSON](20261030T183239.954232Z-scalar-span-trace-7131fede6cac.json) / [CSV](20261030T183239.954232Z-scalar-span-trace-7131fede6cac.csv): all nine subjects qualified, with four original/gated pairs and one nested-signal refusal. Exact comparisons include all GPRs and flags, FP state, stack/data, mask/TLS and fault-PC joins. Reader controls remain separately counted: 112 application, 164 owner and 1,489 terminal refusals. Broader transfer-failure, stale, permission, retirement and whole-program qualification are not supplied by this finite profile.

Their reproduction scripts are `evaluation/inprocess/scalar_span_component.py` and `evaluation/inprocess/scalar_span_trace.py`, each invoked as `python3 -B SCRIPT --expect-revision 7131fede6cac146981b3e1ba039f5edcc55149d2` on one reserved CPU. Neither profile grants performance credit.

The [first merged recorder attempt](20261030T180838.276772Z-checks-1441bb9ed137.json) remains failed. It exposed an automatic successor projection accepting the historical test's deliberately changed count. The repair restores strict historical entry points and makes the newer input projection explicit; all rejection assertions and old test identities remain intact.

The [82-attempt whole-process release trial and recovered numbers](2026-10-30-scalar-span-release.md) remain failed: 60 passed and 22 failed, with no accepted medians, IQRs or speedup. The ten prerequisite cohorts in that report were tested at their recorded earlier revision, not rerun or relabelled here. The target of at most ten times DynamoRIO remains unmet. A reachable-graph execution epoch with immutable static proofs is the next experiment; it has no execution or qualification credit in these receipts.
