# Partial original-address selected controller

This opt-in Linux x86-64 controller composes the sealed first-entry loader with
an immutable fetch borrow, a freestanding decoder, native selected-instruction
completion and original-address single stepping. It is separate from the
parent's ordinary loader and raw-fork profiles. It is not a general dynamic
linker, complete B2/B3 implementation or adversarial sandbox.

Build from the repository root:

```sh
sh tools/page-entry/selected/build.sh
```

The build performs a locked/offline O2 decoder build with an explicit metadata
identity, using the repository's existing `target` directory. It writes
`decoder.a`, source `decoder.d`, compiler identity files, `bridge-selected.so`
and the diagnostic `observe` helper under `target/page-entry/selected`. It does
not execute any fixture or application. `LI2_CC`, `LI2_CARGO` and `RUSTC` can
name exact compiler binaries; otherwise each resolves through `command -v`.
The explicit `RUSTC` path is passed to Cargo, and actual compiler version output
is retained beside the build products. The normal `tools/page-entry/build.sh`
and its output names remain unchanged. A caller can explicitly use
`carrier.py make ORIGINAL target/page-entry/selected/bridge-selected.so OUTPUT`
and the existing sealed-namespace `exec-loader` command with that carrier.

Canonical NOP and register/immediate MOV retain their original typed owner.
A separate owner executes a closed set of 564 decoder instruction codes at
their original addresses: integer arithmetic and memory access, stack operations,
near branches/CALL/RET, integer shifts/rotates, multiply/divide, conditional
results, bit operations/exchanges, and selected SSE2 data operations. The CPU supplies the
actual register, flags, memory and FP results. The runtime validates the actual
post-instruction PC after revoking all temporary executable pages; it does not
predict indirect targets or emulate ordinary instructions.

The generic classifier explicitly checks prefixes and refuses every unlisted code,
including repeated strings, TF-affecting, privileged and transaction instructions.
A separate owner handles exactly canonical REP STOSQ (`f3 48 ab`). Every genuine
iteration trap closes and synchronizes its source pages, checks actual RCX/RDI
progress and validates the closed continuation while retaining the same borrow.
Intermediate traps retain the CPU's RF/TF state; only final completion removes
the injected TF and releases the borrow. Operand faults remain terminal.
Canonical ENDBR64 (`f3 0f 1e fa`) is admitted only under the
existing no-CET profile; additional or ignored prefixes and ENDBR32 still refuse.
The prior measured linker refusal remains a historical failed continuation;
this source addition does not establish a completed gated `ls` run. Random/ID instructions targeting
SP/ESP/RSP still refuse through their separate selected-instruction policy.

The selected inventory describes CPUID, RDRAND, RDSEED, RDPID, RDTSC, RDTSCP and
SYSCALL. Random/ID completion uses one genuine native result with exact width,
flags and destination semantics. Scripted provider controls use a separate API
and never stand in for native evidence. CPUID/TSC use actual private
enable/sample/rearm operations; syscall completion uses the checked raw gateway
and original arguments/results. Source availability is not a coverage claim
for every builtin or syscall. There is no source patching (`source_patches=0`).

## Execution and ownership contract

Application code is NX between events. At most 15 actual instruction bytes are
copied only after authenticating the one or two owned fetch pages, current
object/generation/offset, sealed backing, permissions and alias restrictions.
The descriptive decoder output is not an execution permit. A held borrow blocks
application syscall, mapping, fork and admission mutations; the controller alone
coordinates the step owner's temporary RX and revoke/sync operations. Internal
CPUID/TSC toggles cannot mutate source ownership and finish before continuation.

A genuine pre-entry selftest must complete before entering the original
interpreter. The bridge's actual restored-flags MOV/JMP establishes the initial
RF-clear invariant, with TF clear. The controller carries logical flags forward
through each supported instruction instead of inferring them by masking a saved
page-fault frame. Ordinary steps execute at the original address and require the
actual user fetch fault and exact TRAP_TRACE/vector1 completion. All opened
pages must be revoked and synchronized before the next application fetch. Near
control flow requires its actual destination to be owned, logically RX and
currently NX. A boundary CALL can push a return address on a never-executed next
page; pushing that address does not open or admit the return page. Generic
continuation requires the actual RSP below 2^47 and preserves it without repair;
this does not establish that the stack is mapped or writable. Foreign, nested
or failed-cleanup events refuse. The original kernel
FP frame remains intact; the Rust decoder emits vector instructions, so C's
`-mgeneral-regs-only` is not an integer-only guarantee for the combined runtime.

The profile requires a pinned singleton, no external debugger, no CET and
reserved SIGSEGV/SIGTRAP/SIGSYS. Other asynchronous signals are blocked; original
signal-mask transparency is not claimed. Reserved action queries, mask/altstack
operations, fork/clone/vfork, rseq and threads refuse. The actual vDSO is made NX
and its execution refuses until it has its own qualified owner. Selected code
uses the bridge's SUD-allowed raw gateway. Policies dependent on the original
syscall PC or private handler context, such as seccomp/tracing policies,
remain outside the parent execution contract.
Unexpected reserved faults retain their actual frame and terminate after
revoking the owned prefix. SIGBUS/SIGILL/SIGFPE are process-terminal in this profile;
application fault delivery or restart is not implemented.

The decoder borrows one process-lifetime arena, seals allocation after genuine
table initialization and refuses reentry. Its C ABI is fixed: decoded72 bytes,
stats48 bytes and scan88 bytes; the separate TF classification is40 bytes.
Complete all-start scans are descriptive; this
controller does not turn a scan into full-page permission. Pending failure
prefixes retain actual outcomes and the first failure. Completed counters are
retained, not an unbounded history of every instruction. New builds still need
exact source/archive binding, noimports/noTLS inspection and the bounded
writable-RELATIVE relocation check; old private binary hashes are not evidence
for a newly built artifact.

## Component controls

`tests/decoder` retains all112 original supplied selected forms, unsafe/scan
checks, actual tiny-arena and personality fatal boundaries, and a freestanding
scan harness. These controls decode bytes without executing selected opcodes.

`tests/provider` retains the complete385-case native/scripted/refusal cohort,
its independent saved-state comparator, exact encoding cases, real register/FP
negative variants and nested-native-fault fixture. `cases.py` defines the full
cohort without starting processes; `compare.py` is the unchanged data oracle.

`tests/step` retains the20 same-address native/stepped pairs, including all five
original pairs, full kernel FP frames, actual user selectors, flags, GPRs,
RSP/redzone and source/page comparisons. Thirteen arm-refusal pairs also test
false candidate claims. The four original foreign/nested/TF/RF processes remain.
Its standalone owner uses its original raw-syscall boundary and reserved mask;
the production owner differs only in the reviewed SUD gateway and SIGSYS join.

`tests/fetch` retains18 actual mapping/identity/alias/stale-borrow and failure
prefix cases. Its parser preserves every case-specific comparison. Real raw
EBADF/close failures remain explicitly separate from normal observations.

These sources and their predicates are retained for bounded fresh-process
execution. The build above does not run them, and the smaller connected-stream
cohort does not replace them. Exact committed-source evaluation and component
oracles are separate from mechanism availability. Raw captures, binaries and
host-dependent paths belong only under `target`, not in these product sources.

Reproduce the finite connected cohort on one reserved CPU with
`python3 evaluation/inprocess/page_selected_generic.py --expect-revision REVISION`.
It retains all15 original streams and adds five programs for branch/stack/memory,
boundary CALL/RET, CPUID, RDTSC and RDTSCP. Timestamp results use serialized native
brackets, without an equality tolerance. The separate real-linker diagnostic
reports actual completion or an exact classifier refusal. The older
`page_selected.py` command reproduces the earlier NOP/MOV profile at its recorded
revision; its component helpers and all15 stream predicates remain in use.

`tests/generic` adds21 same-address native/stepped pairs with complete GPR, flags,
selectors, FS/GS, kernel FP, live XSAVE, stack/data and continuation comparisons.
It also retains47 supplied-byte refusals and three actual negative processes:
memory fault, unowned branch target and out-of-domain RSP. The finite connected
programs supplement these independent state comparisons.
Run this oracle on one reserved CPU with
`python3 evaluation/inprocess/page_selected_generic_oracle.py --expect-revision REVISION`.

Run the complete component suite on one reserved CPU with
`python3 evaluation/inprocess/page_selected_components.py --expect-revision REVISION`.
It builds the sealed archive afresh and retains exact native records privately;
its public JSON contains totals, source/tool identities and record hashes.


`tests/integer` adds two separate cohorts of twenty ordinary-integer cases
and one real startup pair each. The original generic oracle remains required,
including its three failed-operation controls. Each new case checks full
native/TF state and memory plus independent literal architectural effects.
Run both `page_selected_integer.py --group 0` and `--group 1` at the same
committed revision as the original generic oracle and connected evaluator.
This finite validation does not claim every encoding or application exception
behavior; divide faults remain outside the supported continuation profile.

`page_selected_repeat.py --expect-revision REVISION` runs the original twenty-two
connected programs plus ten REP programs: counts zero/one/three in both
directions, crossing and end-of-page instructions, repeated owner use, and an
actual first-store write fault. Run it on one reserved CPU. A separate bounded
`LI2_REPEAT` report retains the last request, real permission/query/release
prefixes and counters; the original `LI2_LOADER` report is unchanged. Its parser
requires complete REP evidence and rejects an extra report in every old finite
program. The real-linker diagnostic remains separate from finite completion.

`page_selected_repeat_oracle.py --expect-revision REVISION` separately runs six
same-address native/REP pairs with full state and memory comparisons, all 47
generic refusals, six REP refusal checks and an actual first-store fault. It
builds the current product sources and retains raw records privately. The
public receipt records actual iteration counts and preserves the fault as a
failed operation.

`tests/padding` covers the exact 1–10-byte palette and the observed eleven-byte
`66 66 2e 0f 1f 84 00 00 00 00 00`, without permitting other repeated or segment
prefixes. Run
`python3 evaluation/inprocess/page_selected_padding.py --expect-revision REVISION`
on one reserved CPU. Two bounded processes retain the original twenty pairs and
add eleven full-state native/stepped pairs: the new form ending at a page boundary
and all ten crossing splits, plus two genuine startup pairs. Historical padding
refusal entry two is intentionally promoted to accepted classification and these
positive cases; its earlier refusal receipt stays historical. All 47 generic and
the other eleven padding refusals remain, with two new neighbors (one extra 66 and
a changed displacement) still refused. The complete record layout and resource
bounds are unchanged; unused slots in the second record must be zero. The original generic oracle, its actual failed-operation controls and
the connected REP cohort remain separate requirements. Padding support alone
does not establish a completed real-linker run.

Canonical XGETBV (`0f 01 d0`) executes only when the genuine NX frame has
ECX=0. Upper RCX bits are ignored as specified by the instruction; they remain
unchanged. An authenticated nonzero ECX refuses before source opening or TF
insertion. The CPU supplies the actual XCR0 result in zero-extended EAX/EDX.
ECX=1 state-use observation and noncanonical encodings remain outside this
profile. Unsupported XSAVE/OSXSAVE hardware remains a terminal failure.

`python3 evaluation/inprocess/page_selected_xgetbv.py --expect-revision REVISION`
runs six full-state XCR0 pairs plus the startup pair, all 47 old and nine new
encoding refusals, three genuine pre-open index refusals and one actual native
invalid-index fault. Run on one reserved CPU. Failed operations retain exit 125
and are counted separately from completed pairs. All existing generic, integer,
padding, REP and component suites remain required.

Legacy XMM PCMPEQB/W/D, PCMPGTB/W/D, PMINUB, PMAXUB and r32 PMOVMSKB
execute through the same original-address owner. MMX, AVX/EVEX and REX.W
movemask encodings remain refused. Run
`python3 evaluation/inprocess/page_selected_sse2_compare.py --expect-revision REVISION`
on one reserved CPU for two bounded cohorts with 36 new pairs and two startup
pairs. Literal lane/movemask expectations supplement the unchanged full-state
comparison. The cohorts include register and aligned-memory forms, low/high
registers, page endings and crossing fetches. An actual inaccessible-memory
instruction remains a failed operation with native and stepped fault records.
All prior suites remain required; this addition does not establish general SSE
encoding support or completed real-linker execution.

Scalar BSF/BSR r16/r32/r64 register and memory forms use the same
original-address owner. Run
`python3 evaluation/inprocess/page_selected_bitscan.py --expect-revision REVISION`
on one reserved CPU for three bounded cohorts: 48 new pairs and three startups,
including zero/nonzero sources, low/high registers and crossing fetches. Literal
effects constrain ZF and nonzero destination indices; exact native comparisons
retain every actual flag and zero-input destination. Two actual inaccessible
memory commands remain failed operations, with native and stepped fault records.
All 47 old encoding refusals and 24 additive refusals run in each process.
All prior suites remain required; no general exception continuation or completed
real-linker execution is claimed.

The separate `build-register-run.sh` build enables a bounded register-only
code cache. Original source pages stay nonexecutable. A run copies at least
two canonical NOP or register MOV instructions from an already-owned source
window of at most 15 bytes, then jumps to its complete original guard.
Memory operations, selected instructions and branches remain guards. The
original NX fault validates the completed run and dispatches that guard
through the existing owner with a fresh source borrow.

The cache owns 64 immutable private pages. Each publication authenticates the
held source and plan, fills an RW page, changes it to RX, synchronizes and
verifies the complete page. Hits recheck the actual source and RX publication.
A full cache takes the existing original-address path; no slot is recycled.
Incomplete publication and interrupted owners retain their failure prefixes
and cannot resume the application. The default build remains the reference.

`python3 evaluation/inprocess/page_selected_register.py --expect-revision REVISION`
runs nine literal inputs as genuine publication/hit pairs, then fills all
64 slots, exercises a genuine fallback and checks a hit after capacity fills.
It retains all 18 semantic records and five capacity/fallback/hit records.
The other capacity cycles retain in-process full-state checks and hashes.
This finite oracle does not establish arbitrary relocation, application
completion, signal/thread support or a performance result.

`python3 evaluation/inprocess/page_selected_register_perf.py --expect-revision REVISION`
measures the first publication and 1/10/100 later hits at the same original PC,
with separate bracket-only controls. Run it on one reserved CPU. It uses the
optimized opt-in bridge and records every raw interval in TSC ticks under
`evaluation/inprocess/results/`. The intervals include clock, CPUID and page-gate
work; they do not isolate publisher cost. Any workload or finalization failure
withholds timing credit for the entire cohort. The separately qualified full-state,
publication-failure and capacity oracles remain required.

Additional original-address SSE2 qualification scripts are
`page_selected_sse2_halves.py`, `page_selected_sse2_byte_shift.py` and
`page_selected_sse2_movd.py` under `evaluation/inprocess/`. Each takes
`--expect-revision REVISION` and requires one reserved CPU. They exercise finite
literal full-state effects and instruction-page splits; memory suites also
retain genuine failed native/stepped accesses. The exact eleven-byte alignment
NOP is covered by `page_selected_padding.py`: that previously refused exact
form is now positively qualified, while its historical failure remains recorded.
All other prefix restrictions and owner predicates remain. Real dynamically
linked applications still stop at unsupported instructions, as recorded in
the evaluation receipts.

Both selected builds share physical `/proc/self/maps` rows only within one
uninterrupted handler phase. Each query retains its ownership, seals,
permissions and source-byte checks. Execution, application syscalls, unwhitelisted raw calls,
nested events and failures invalidate the rows; later handlers acquire fresh rows.
`page_selected_maps.py` qualifies four existing positive/capacity cases, fourteen
terminal controls and nine new acquisition/invalidation modes on one reserved
CPU. The connected and first/hit measurement scripts exercise the production
bridge separately. Exact revisions, commands and numeric results are recorded
in `evaluation/inprocess/RESULTS.md`; finite timing results do not establish
real-program completion.

Canonical RDSSPQ r64 uses a separate observed-state entry. Two adjacent actual
RDSSPQ reads must preserve distinct destination seeds before either source page
opens. The status syscall remains diagnostic; errors do not grant permission.
The original strict query entry remains available and retains its own refusal
controls. Run `page_selected_rdssp_observed.py --expect-revision REVISION` on
one reserved CPU for all 16 destinations, full native/TF state, and five failed
pre-open controls. This qualifies only observed disabled shadow stacks, not
enabled-CET execution or general CET support.

`page_selected_sse2_movq.py` qualifies nine canonical MOVQ r64/m64 encodings,
including the observed loader transfer, with full-state and genuine fault
comparisons. The earlier MOVD suite explicitly retains and positively checks
the two newly admitted neighbors; its other refusal cases remain.

Canonical RIP-relative LOCK ADD/SUB m32 with sign-extended imm8 execute on the
CPU at their original addresses. Only the exact `f0 83 05 disp32 imm8` and
`f0 83 2d disp32 imm8` forms receive this prefix exception. Run
`page_selected_lock_add.py` and `page_selected_lock_sub.py` with
`--expect-revision REVISION` on one reserved CPU. Both share the full native/TF
state comparator and retain actual no-access/read-only failed RMW controls.
Their finite qualification covers aligned four-byte operands within one cache
line; it does not establish concurrent atomicity, split-lock or device behavior.

The real-program and legacy diagnostic failures remain visible in the numeric
receipts. Current instruction coverage still does not complete the tested
dynamically linked programs; their performance fields remain null.

The selected profile additionally accepts five canonical PMAXUD forms, exact BND RIP-relative indirect JMP `f2 ff 25 disp32`, and exact unmasked VPBROADCASTB `62 e2 7d 48 7a c6` (ESI's low byte to ZMM16). BND requires a fresh actual XCR0 observation with MPX components disabled before opening source pages. These additions do not enable general F2/EVEX prefix acceptance or enabled-MPX execution.

`python3 evaluation/inprocess/page_selected_register_time.py --expect-revision <full-commit> --program true --disable-rseq` enables the bounded fixed-site clock observer. Successful discovery and final program completion are mandatory before real timing is published. Its finite native/cache controls qualify clock capture and terminal error handling; they do not substitute for real-program completion. All observed real discovery runs through bb425428 remain failed with null real timing. See the exact per-workload commands and outcomes in the milestone evidence; no application speedup or complete dynamic-program coverage is claimed.
