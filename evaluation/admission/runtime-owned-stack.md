# Opt-in original-stack CALL and RET

`DynamicRuntimeOptions::stack` defaults to `RuntimeStackProfile::Refuse`.
`OriginalResidentWord` adds exact unprefixed `E8 rel32` CALL and `C3` RET to the
initial singleton runtime. It executes the original instruction at its original
address. Prefixed variants, indirect CALL, far returns, RET with an immediate,
PUSH/POP and other memory instructions retain their existing refusals. Selected
instructions retain their separate provider and completion contracts.

The unsafe launch contract additionally requires exclusive writer and alias
custody of the original stack, no external pager or userfaultfd handler, and the
same supported component-9 XSAVE layout on every CPU available to controller or
tracee. Actual stack metadata, resident/exclusive pagemap bits, AC and PKRU are
checked; those observations do not establish the caller's custody obligations.
This finite profile promises neither paging nor fault transparency. The initial
single-task, immutable-source, architectural-control and no-opaque-context
requirements remain in force.

## Return addresses and publication

A CALL ending exactly at a page boundary pushes the next page's address even
when that page has never executed. Before the first private opening action, the
owner therefore appends a conservative potential-return row containing the
full current state, immutable source identity, exact encoding, next PC, target
and stack slot. The row survives failure, later RET and deadline expiry. It is
not a claim that the CALL completed and cannot authorize execution.

The native producer opens only the pages containing the actual encoding. A
page-aligned return destination is outside that range. An encoding that itself
crosses a page boundary needs both fetch pages; that is a separate case. RET
single-steps to its actual target and stops before the target instruction can
execute. Ordinary admission must independently authenticate any later execution
there. These rules preserve the qualified publication boundary rather than
inferring safety from whether a destination page has executed before.

## Captured state and failure custody

Startup retains the actual original stack descriptor, complete metadata,
control-layout observations and full restored state. Each operation freezes its
eight-byte operand from the real current RSP. Unaligned words may require two
aligned PEEK requests and two resident/exclusive pages. The frozen slot does not
follow the successor RSP.

A is captured while the source is closed; B follows opening and its final
source check; C follows the one actual original-instruction trace; D follows
closing and its final source check. Each capture retains metadata, pagemap,
request outcomes, the initialized word envelope, an independent full state read
and complete maps. Pagemap eligibility precedes PEEK, since PEEK itself could
change residency. CALL changes exactly the eight slot bytes to the return PC;
RET changes none. Full GPRs, flags, XSTATE, signal mask and neighboring envelope
bytes must match the operation's exact equations.

The normal path has six private releases and one original single-step, with
seven actual waits. C must validate before the registry records NativeCompleted.
A one-shot native completion is then consumed by the census, which appends six
refreshes, one consumption and one current origin. The final history token,
current origin and native stop must agree. No fallible callback separates census
commit from current/control-lineage installation.

A fault retains a distinct failed-held diagnostic. It supplies no successful C,
normal closing sequence, completion seal or new current origin. Every partially
allocated or partially observed owner remains retained through physical cleanup.
Allocation errors and panics settle each installed prefix before another native
read/effect or cleanup; the original failure stays distinct from any secondary
settlement discrepancy. Null header allocation retains the pending reservation.
An already installed header is accounted even if allocation has not started.

## Managed evidence bounds

Startup reserves three 65,536-byte profile buffers and two fixed owning index
arrays sized by the lifetime origin ceiling. Each attempt reserves exactly one
origin and seven witnesses, with zero new epochs, reports or plan-history units.
The byte bound includes root source/current buffers, native private-control and
A/B/C/D buffers, sixteen census state buffers, the fixed evidence record, exact
owning headers and explicit temporary terms. CALL additionally prepays one
full-state potential-return record. Moving a CALL Box to its fixed ledger slot
or moving census buffers to histories adds no second payload debit.

The payload-only floor is 46 × 65,536 bytes per RET and 47 × 65,536 per CALL,
before source-window bytes, headers, startup and temporary terms. Under the
unchanged 64 MiB ceiling this gives only optimistic upper bounds of 22 RET or
21 CALL attempts; actual mixtures fit fewer. Reservations and histories are not
refunded or removed. These formulas describe managed evidence, not process RSS,
allocator metadata or compiler stack size. They are not performance results.

## Validation contract and reproduction

Native controls require an independent raw SINGLESTEP lane, complete own-lane
state and whole-stack equations, exact source and mapping observations, actual
one/two-page fetch cases and retained CALL/census identities through cleanup.
Positive whole-stack reads are disclosed residency setup. Residency-negative
fixtures observe pagemap before any eligibility-changing stack read. AC/PKRU
interventions use actual setters and readbacks; the post-B fault cases require
the specified real fault and cannot count an earlier refusal as equivalent.

Lower raw-I/O fixtures and copied-record comparator controls are identified
separately. A two-pin raw fixture does not qualify connected singleton
admission. `close(-1)` establishes only its actual raw error; a separate null
GETREGS request is not a failed production StateSlot group. An injected closed
observer rejection is not evidence that the real maps changed. Allocation fault
controls exercise actual installed owners with injected error/panic boundaries.
These distinctions remain part of the evidence, even when the enclosing native
method passes.

The recorded drivers retain exact revision/source/configuration hashes,
hardware, relative command arguments, typed outcomes and physical cleanup
summaries under `evaluation/admission/results/`. Use one unchanged eight-CPU
reservation, incremental compilation disabled, and the established toolchain
setup in [initial coalescence](initial-coalescence.md):

```text
python3 evaluation/admission/run.py --expect-revision <40hex>
python3 evaluation/admission/default_parallel.py --expect-revision <same-40hex> --cohort unit
python3 evaluation/admission/default_parallel.py --expect-revision <same-40hex> --cohort fork
```

The first driver includes the four required Cargo checks, recorder controls and
the separate serial launcher cohort under their existing limits. The repetitions
use Cargo's default test parallelism. Every named current native method must
have an explicit successful result; missing, failed, ignored or duplicate rows
cannot qualify. All prior native identities, corpus fields and historical checks
remain required.

This document specifies implementation and validation obligations. It records
no execution result. Hand-encoded CALL/RET fixtures do not establish support for
a compiler-produced CALL consumer; the existing identity/termination C consumer
has its own narrower artifact-bound result. Further results require clean,
exact-revision receipts. Finite evidence here targets claims 1, 2 and 4. Loader,
TLS, general memory/I/O, lifecycle composition, dlopen/JIT, application-scale
performance, hybrid release and claim 3's software clock remain separate work.
