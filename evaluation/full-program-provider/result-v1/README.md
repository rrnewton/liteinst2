# Full-program capture: site-cap refusal retained

At `83e664969612a1ffe570518146c5eda60a851109`, the pinned provider captured 13,143 instruction rows from the complete PLDI2020 e9patch input. The existing importer verified those heads and retained all 2,053 `j*` sites. Material generation **refused at the unchanged 1,024-site cap** (exit 2). No planner, backend or subject execution followed.

[receipt.json](receipt.json) contains exact commands, source/tool/output hashes, counts, environment, CPU/load and wall observations. Four provider stages and the bridge build exited 0; material refusal also closed normally. All owners report complete cleanup and zero rescued descendants. Timings are not performance qualification.

Use the existing [provider instructions](../full-program-provider/README.md) at the executed revision under an external one-HARD-CPU reservation and the recorded process-owner bounds. `${ROOT}` is the checkout; `${OUT}` is a fresh direct child of `target/evaluation`; `${ORIGINAL}` is the pinned input; `${CSV}` is its captured DISASM file; `${MATERIALS}` is an absent output directory. `${RUST_BIN}`/`${CARGO_BIN}` select installed tool paths. The receipt's `bridge-*` commands build and run the bridge; the expected result is refusal. Its complete-code/noncode-gap premise remains independently caller-supplied.

No fitting subset, widened bound or promoted failure is used. Prior 16 MiB refusals, 4,224 fixture pairs and the separate strict 1,342/2,048 profiler failure remain unchanged. Raw captures/logs remain private.
