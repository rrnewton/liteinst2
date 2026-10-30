# Merged generated-loop qualification, 2026-10-30

ADDS: compatibility between the generated dynamic-loader hash loop and main's routed native/ELF producer contracts, with complete merged-tree validation. This milestone supports claims 1 and 4 (publication and tactic validation); it adds no performance claim.

Tested source: `68685d9c5b43e6a915858c0da9c63d22aa702040`, containing main `ac8b2abf3499ad80def4e650c9b14834000b65ab` and the previously qualified generated-loop implementation. The source tree was clean and unchanged through each run. Hardware: AMD EPYC 9D85, family 26/model 17/stepping 0, microcode `0xb101066`, x86-64, kernel 7.1.3; Rust/Cargo 1.97.1. Full hardware and command receipts are linked below.

| Required check | Result | Seconds |
|---|---:|---:|
| Recorder | 350 passed | 176.768 |
| Format | passed | 9.157 |
| Strict workspace Clippy | passed | 46.875 |
| Workspace tests | 3,768 passed, 37 ignored, 0 failed; 106 complete harnesses | 687.876 |
| Workspace all-target/all-feature check | passed | 31.693 |
| Serial launch tests | 1,039 passed, 0 failed/ignored; 27 complete harnesses | 133.517 |

The original bounds remain: recorder/format/Clippy/check/serial each 180 seconds, workspace 900 seconds. Recorder used four workers, Cargo four build jobs, tests four threads, incremental compilation disabled; four CPUs were reserved. These durations describe validation runs, not application performance.

The native owner oracle qualified all 25 subjects: nine native/gated pairs and seven required owner refusals. Fourteen application runs completed; two reference and two generated read faults remained required failures. All 234 application-reader, 472 owner-reader and 542 terminal-reader corruption checks refused. The component oracle qualified all nine modes: seven generated chunks, six completed loops and two required read faults, with all 373 reader corruptions refused. Both suites compared complete architectural state and retained their original resource bounds. Owner ran on reserved CPU 4; component on CPU 1. Neither grants whole-program timing credit.

The merged inventory records 98 additional test instances from main. Two unsuccessful validation attempts remain failed: revision `9acead4a23593e805d70f0775118c7345fca1be4` exceeded the unchanged recorder deadline; revision `56c3314606db0d381c583bd5fb5df134b06d035c` failed the newly added example-header parser test. The fixes add a separate bounded cache for large immutable byte hashes and recognize the exact new Cargo example header. Fresh file reads, source comparisons, all old assertions and malformed-header refusals remain. This successful run does not establish a comparative speedup for the hash cache.

Reproduce at the tested revision, with the listed toolchain, reserved CPU counts and original evaluator bounds:

```sh
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=4 python3 evaluation/inprocess/checks.py --expect-revision 68685d9c5b43e6a915858c0da9c63d22aa702040
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 python3 evaluation/inprocess/unrolled_hash_owner.py --expect-revision 68685d9c5b43e6a915858c0da9c63d22aa702040
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=1 python3 evaluation/inprocess/unrolled_hash_component.py --expect-revision 68685d9c5b43e6a915858c0da9c63d22aa702040
```

The last two commands each require one reserved CPU. Run them serially with the check driver. The JSON receipts bind the exact source, scripts, compiler, runtime libraries, captures and cleanup; CSV files contain the numerical oracle rows. Raw logs remain private.

- [Six checks](20261030T094505.918042Z-checks-68685d9c5b43.json).
- [Owner JSON](20261030T100324.535375Z-unrolled-hash-owner-68685d9c5b43.json) and [CSV](20261030T100324.535375Z-unrolled-hash-owner-68685d9c5b43.csv).
- [Component JSON](20261030T100614.757332Z-unrolled-hash-component-68685d9c5b43.json) and [CSV](20261030T100614.757332Z-unrolled-hash-component-68685d9c5b43.csv).
- [Preserved recorder timeout](20261030T092809.775524Z-checks-9acead4a2359.json) and [preserved parser failure](20261030T093911.339292Z-checks-56c3314606db.json).

The last whole-program cohort still failed qualification and the 10× DynamoRIO target remains unmet; its [original report](2026-10-30-generated-loader-loop.md) retains those limits. The next scalar block-cache implementation is source-reviewed only and is not included in this tested revision.
