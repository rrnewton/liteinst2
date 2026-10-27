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
A separate owner executes a closed set of 544 decoder instruction codes at
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

`tests/padding` qualifies the exact 1–10-byte canonical NOP palette, including
`66 2e 0f 1f 84 00 00 00 00 00`. This single additional ten-byte encoding does
not permit segment prefixes on other instructions. Run
`python3 evaluation/inprocess/page_selected_padding.py --expect-revision REVISION`
on one reserved CPU for twenty full-state native/stepped pairs: page-end
placements and all nine splits of the ten-byte form. It retains the genuine
startup pair, all 47 old refusal controls and twelve additional near-neighbor
refusals. The original generic oracle, its actual failed-operation controls and
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
