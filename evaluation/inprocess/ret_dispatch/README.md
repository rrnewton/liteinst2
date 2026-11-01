# Experimental RET observations

This fixed runner retains the original 32 unstepped C3 observations and RET671 byte/model component, then requires the existing eight-plan/924-model planner and compact component. It runs the complete 16-case / 24-lane emitted RET matrix twice: first at the original low placement, then with a high code cluster and low window separated by more than signed rel32 reach. The supplied directory/window values are test inputs, not production owner authority. A loaded unknown target is observed at its dedicated stop and is never resumed or replayed. This standalone runner does not establish runtime owner authority; the separate nine-subject owner recipe remains mandatory for its own finite scope.

Use Linux x86-64, Python 3.11 or newer with assertions, GCC, GNU binutils and the normal glibc loader. Reserve one CPU and keep that reservation for the CALL217 prerequisite and this command. `--cpu` must equal the singleton inherited affinity. Use a clean checkout at the same full expected revision for both commands. This runner does not reserve a CPU itself.

First run the existing [CALL217 producer](../call_push_native/README.md), retaining its complete private receipt, captures and artifacts. Its whole 217 pairs / 434 lanes, exact source/CPU/hardware, all command bounds and cleanup are reauthenticated before RET work. Its result stays `observed_unqualified`; this is not a CALL/PUSH equivalence claim. Obtain the exact SHA-256 of that receipt without changing it.

Prepare or reuse an independently authenticated decoder archive with the existing `linked-epoch,mov-guard` recipe described in the [CALL component README](../call_dispatch_component/README.md). Supply the complete archive SHA-256. The runner verifies its whole bytes and required providers; a hash alone does not establish the archive's source/build provenance. Retain that external build evidence separately. The archive is used in place and is never rebuilt or copied here.

```sh
python3 -B evaluation/inprocess/ret_dispatch/run.py \
  --expect-revision FULL_COMMIT_SHA \
  --call217-receipt PATH_TO_CLOSED_CALL217_RECEIPT \
  --call217-receipt-sha256 FULL_RECEIPT_SHA256 \
  --archive PATH_TO_AUTHENTICATED_DECODER_ARCHIVE \
  --archive-sha256 FULL_ARCHIVE_SHA256 \
  --cpu RESERVED_CPU \
  --output target/evaluation/inprocess/ret-observations-attempt-1
```

The output must be new. There is no case selector, retry or reuse of a prior RET result. The original RET32 producer/reader/recipe and both native assembly/recipes remain unchanged. The emitted-native fixture adds a separate `--high` invocation of the same inspected executable, while its reader retains the six unchanged frame/context helpers in `frame.py`. The RET component recipe includes the planner-required CALL define; compiler flags and limits remain otherwise unchanged, with only the existing diagnostic additions `-save-temps=obj` and `-Wl,--trace`. Native recipes retain their original flags and have no linker-trace claim. Every actual compiler-M dependency, compiler/subtool, prebound compiler-selected link input, dynamic dependency and interpreter alias is checked. Both native executables pass the existing complete bootstrap/return inspector before execution. Unknown dependency forms fail.

All children use the existing `page_selected_process.invoke` owner. Build/metadata commands retain 30 CPU seconds, 60 wall seconds, 512 MiB address space and 16 MiB output. Component, native, bootstrap inspection and reader commands retain 5 CPU seconds, 15 wall seconds and the same memory/output limits. Every child must exit zero, be reaped and close all descriptors. Source/input/mode/alias/loader-presence/affinity checks cover the entire run. Any failure preserves the partial record and leaves the overall run failed.

The fixed outcomes remain separate:

- RET32: 32 original C3 executions, labeled `observed_unqualified`. The reader reports actual SP commitment and faults without prescribing replacement behavior. All original full-state/stack checks remain.
- RET671: exact stdout `ret-dispatch descriptors=15 decoded=795 models=671 forms=512 arguments=6 bindings=16 corruptions=20 interiors=459 geometry=4 recovery_controls=16 far_models=4 literal_controls=12 relocations=6`. It reconstructs the complete 285-byte emitted body, 512-byte image (including the eight-byte landing literal at offset 504) and all 53 boundary rows; it does not execute generated instructions.
- RET planner: the original eight plans / 924 models, 167,772 compact recoveries and every original refusal, geometry, argument, corruption, interior and landing control remain. Two far placements and 24 literal/displacement corruption controls are additive.
- RET16/24, separately at low and high placement: six native/generated hit pairs, two native/generated load-fault pairs, four generated-only stopped loaded misses, two before-load misses and two generated-only post-load word-mutation observations. The two traced paths have 45/35 events, 38/35 distinct row PCs and a union of 38. Initial NX entry is separate. These are the observed boundaries, not all 53 component rows. The high invocation uses one actual 24-page source/target/generated/spill cluster and the unchanged low window; its raw geometry must prove a loaded-miss displacement below −2^31. Both invocations retain the same complete matrix and bounds. Each lane retains full before/after GREG/FP/context/TLS/stack, and each mutation lane an additional full checkpoint; intermediate TRACE rows retain integer/flags/spill/recovery observations.

`receipt.json`, raw chunks, complete reader outputs and build artifacts remain private. `summary.json` is the compact host-path-free projection, with per-case outcomes/raw digests, source/hardware/archive/tool identities, command/capture digests and closure. No full raw or archive copy is published. Numeric stack addresses are omitted from public rows after preserving their exact differences; complete addresses remain in the authenticated private result.

The [historical observations](../results/2026-10-31-ret-dispatch-observations.json) were produced by the source-reviewed private collectors at the revisions they name. This portable runner is a later source adapter and has not been executed. This high-bank successor has no execution evidence. The loaded-miss jump now reads the sealed slot literal; original-source and spill rel32 checks remain. Historical failures and observations keep their original source identities and statuses. The old 392/522 gates, real-program completion and the performance target remain unmet. A production owner must still authenticate directory/window lifetime and copy/consume any loaded-miss continuation exactly once, including native fault and asynchronous interruption semantics.
