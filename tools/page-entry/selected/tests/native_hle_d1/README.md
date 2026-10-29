# D1 HLE byte-policy refinement

The policy refines only the LOCK-derived transaction bit for a bounded D1 opcode plus a present ModRM. Every original offset, core and implicit-HLE scan remains; no accumulated bit is cleared. Opcode and ModRM must fit 15 bytes from the candidate hint or preceding LOCK. Missing opcode/ModRM and overlong candidates remain conservative. Optional addressing bytes may be absent: this proves absence of HLE, not valid or complete decoding. No VEX boundary, host CPUID, IFUNC choice or current NX permission grants admission authority.

D1 Group 2 /0..7 encodes ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR. The [AMD64 Architecture Programmer's Manual, Volume 3, publication 24594](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24594.pdf), revision 3.38, section 1.2.5 (printed page 12), permits LOCK only for an exhaustive list excluding these operations. Table A-6 (printed page 535) explicitly lists /6 as redundant SHL/SAL, footnote 5. [Intel XED's vendor-maintained opcode data](https://github.com/intelxed/xed/blob/main/datafiles/xed-isa.txt) independently defines SHL_MEMv_ONE_D1r6 and the undocumented register alias, without LOCKABLE/HLE attributes. Intel mnemonic tables omit /6; this proof uses AMD's explicit redundant encoding and the XED entries. The [iced-x86 1.21.0 decoder](https://github.com/icedland/iced/tree/v1.21.0/src/rust/iced-x86/src) supplies separately checked decode/metadata corroboration.

The C probe includes the complete original native_pages/policy_probe.c and invokes it first. Its entire population and exact first output line remain mandatory. Additional actual-policy checks cover all 256 ModRM bytes, both LOCK/hint orders, all 27 prefix bytes, 15/16-byte endpoints, optional-address truncations, every offset for five retained libc contexts, other opcode neighbors, independent core/HLE bits, and actual inaccessible/read-only buffers. Its second line is exactly `{"version":1,"d1_checks":[40960,20590,1082,1147]}`.

The separate iced component checks 24 literal D1 codes, seven mode/operand forms times 256 ModRM bytes times two vendor options, 14,336 strict invalid-LOCK cases, 3,102,930 all-offset decodes and 42 actual HLE positive decodes. NO_INVALID_CHECK is used only after exact normal invalidity to describe the target opcode; it supplies no validity or admission authority. These are decoder settings for 16/32/64-bit modes, not execution in 16/32-bit processor modes.

Run the bounded component evaluator at an exact clean committed revision, on one externally reserved CPU:

```sh
python3 evaluation/inprocess/page_native_hle_d1.py --expect-revision "$REV"
```

It retains the existing Build tool/config/registry closure, observes the mode crate's own locked metadata and dep-info, compiles the actual policy translation unit, and compares both exact component outputs. The build recipe uses only the repository `target` Cargo cache, then copies the mode binary and dep-info to the unique retained output. Compiler includes, actual ELF/dependencies, inputs, artifacts, captures and process cleanup are checked before and after. Component bounds remain 30 CPU seconds, 256 MiB address space, 1 MiB files and 45 seconds wall time. C compilation uses 5 CPU seconds/512 MiB/16 MiB/15 seconds; Rust uses the existing Build profile of 120 CPU seconds/2 GiB/128 MiB/150 seconds. Existing process cleanup is reused. No application bound changes.

The following separate, unchanged commands remain required before claiming runtime qualification. Use complete same-revision receipts in POS, NEG49 and RSEQ17; do not select individual cases:

```sh
python3 evaluation/inprocess/page_selected_bmi1_register.py --expect-revision "$REV"
python3 evaluation/inprocess/page_selected_oneshot.py --expect-revision "$REV"
python3 evaluation/inprocess/page_selected_oneshot_failure.py --expect-revision "$REV" --positive-receipt "$POS"
python3 evaluation/inprocess/page_selected_rseq_application.py --expect-revision "$REV" --fast-memset
python3 evaluation/inprocess/page_selected_rseq_native_boundary_run.py --expect-revision "$REV" --positive-receipt "$POS" --negative-receipt "$NEG49" --rseq-receipt "$RSEQ17"
python3 evaluation/inprocess/page_release_workload_performance.py --expect-revision "$REV"
```

The boundary runner executes all 16 original registered-native cases and four boundary cases, after the complete 6/49/17 prerequisites. The six BMI1 cohorts retain 102 full-state native/TF pairs, including 48 BLSMSK instructions. No source, flags, FP/XSTATE, memory, RF, rseq, revoke/query/release or outcome comparator changes. Original RF/gateway suites remain unchanged; this component receipt does not stand in for them.

Admission invariants remain exact: sealed immutable source and a full page plus logical executable 14-byte halos; stable backing/alias/current-map identity; singleton blocked-signal ownership; low-address exclusion; no held fetch; admissions equal closed before opening; original rseq prepare/publish; actual permission and map verification; all-page closure and complete NX/FP/frame/retry proof. No page-generation cache or retained two-page native domain is added.

The refinement establishes no IFUNC choice, speedup or deadline fit. Run all 20 unchanged performance subjects only after qualification, retaining every failed or limited outcome. The fixed workload remains 1,024 warmup calls plus eight batches of 8,192 calls under its original 30 CPU seconds/60 seconds wall bound.
