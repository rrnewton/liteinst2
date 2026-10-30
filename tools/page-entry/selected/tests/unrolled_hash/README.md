Private source candidate only; no compilation, decoder execution, native operation, or reader replay has been performed for this fixture.

The new fixture qualifies the distinct 64-copy planner, not the existing whole-function, register-run, native-page, or old hash-loop owner. Root still owns runtime integration. It reuses the unchanged `region_cache/machine.S` and `machine.h` for all sixteen GPRs, complete flags (including hardware TEST AF), selectors, 65,536-byte XSTATE images, private observer stack, and restoration of the host state. Existing failed component cohorts remain failed.

The fixed nine process modes each execute two lanes on the same actual sealed source/image and input:

| Mode | Data/seed | Expected boundary | Process exit |
|---|---|---|---|
| 0 | NUL at byte 1 | Original stop after 1 copy | 0 |
| 1 | NUL at byte 2 | Original stop after 2 copies | 0 |
| 2 | NUL at byte 63 | Original stop after 63 copies | 0 |
| 3 | NUL at byte 64 | Original stop after 64 copies | 0 |
| 4 | NUL at byte 65 | Original head after 64 nonzero copies; loop incomplete | 0 |
| 5 | NUL2, high full64 initial RDX, wrapping initial RBX, AF initially set | Original stop after 2 copies | 0 |
| 6 | NUL64 at final readable page byte | Original stop without reading the next page | 0 |
| 7 | First MOVZX addresses actual PROT_NONE page | Required original/generated read fault, copy0 | 125 |
| 8 | 63 readable nonzero bytes then actual PROT_NONE page | Required original/generated read fault, copy63 | 125 |

The original lane executes the exact original 24 bytes under an explicit reference TF observer. It validates all expected instruction successors and stops immediately after the actual eighth instruction of the terminating copy or copy64. This avoids pretending the NUL65 loop naturally stops at that bounded endpoint. The raw TF entry/exit frames remain in the record. Only that observer's TF bit is removed before the final machine capture; no arithmetic flag, AF, general register, application stack, or FP byte is normalized. The generated lane returns through genuine original head/stop NX with no TF events. Both lanes use the same source39, data, stack, registers, flags, and full actual initial XSTATE. This reference is not the production TF owner and earns no production owner or timing credit.

The handler never reads application data to predict a terminator or result. The generated CPU executes identical MOVZX addresses under the kernel-restored application XSTATE/PKRU. The fixture's independent defined-GPR recurrence runs only after the observed invocation and uses the separately retained fixture input. Actual undefined AF is compared to hardware original, never predicted or masked. Every byte of both 65,536-byte live XSTATE images, 160-byte application stack slice, and 8,192-byte readable data area is compared. The two genuine fault frames are compared in full after only the explicit reference TF removal and exact generated-PC to original-MOVZX association. Required faults are terminal refused operations; no fault resumption or completed operation is credited.

Actual authority setup uses memfd seals15, distinct private source/image pages, exact stat and maps identities, whole4KiB readback, no writable alias, exact near placement and sync-core. Four real alias/seal controls execute before entry. Source stays NX throughout generated execution. Cleanup attempts independent revoke/sync/unmap/close actions and preserves the first error; a failure within the alternate-stack handler exits nonreturningly and cannot claim successful cleanup. The fixture owns all mappings for one process; retained RX authority between application invocations, rseq publication, unexpected/nested production ingress, source mutation, and arbitrary application entry remain unimplemented runtime-owner obligations.

Mode0 also invokes the real planner/map API for all513 exact heads and all1284 interior misses, 26 changed body/guard bytes, wrong extents/nulls/overflow/rel32 distances, and34 malformed complete-plan controls: 70 supplied refusals total. These are supplied description controls, separate from native operations. All nine modes preserve the same seven-completed/two-required-fault population and must pass before any cohort qualification; no retry, omitted mode, time threshold, or timing credit is defined.

The build recipe takes `ROOT SELECTED_DIR DECODER_ARCHIVE OUTPUT_DIR`. SELECTED_DIR contains the actual reviewed planner/header (or their eventual installed paths). The existing Build owner must pin all recipe/TU/`cc -M` header inputs, decoder archive/registry facts and compiler before compilation, then pin the resulting ELF, actual PT_INTERP/runtime libraries and complete captures before and after all commands. The recipe is O2 with the existing FAST_EQUAL/FAST_MEMSET implementations; it does not change global optimization flags or build a second Rust planner.

The native owner must launch modes0..8 at one exact committed revision and reserved CPU, each with the unchanged **5 CPU seconds, 15 wall seconds, 512 MiB address space, 16 MiB file size** bounds, actual FD3 record capture, and `GLIBC_TUNABLES=glibc.pthread.rseq=0`. Use the existing `page_selected_process.invoke(..., record=True, step=True)` and command cleanup/finalization predicates. This document does not authorize or perform those launches. Expected exits are `[0,0,0,0,0,0,0,125,125]`; each complete record is556,032 bytes and stdout is one bounded numeric JSON line, stderr empty.

Reader API: `check(record_bytes, stdout_bytes, stderr_bytes, actual_exit, mode) -> numeric dict`. Minimal retained-record reproduction is `python3 tools/page-entry/selected/tests/unrolled_hash/check.py RECORD STDOUT STDERR ACTUAL_EXIT MODE`. Root's eventual evaluator must bind actual process outcomes and source/build/capture closure; the reader alone supplies none of those proofs. No performance measurements or whole-ls coverage inference are provided.
