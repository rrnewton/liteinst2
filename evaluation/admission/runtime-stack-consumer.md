# Finite compiled C CALL/RET consumer

This experiment compiles one fixed C program, then runs the authenticated ELF
directly, through the public runtime API, and through an independent raw/admitted
observer. The program executes `getpid`, calls a separate `add_seven` function,
executes `gettid`, and passes the computed difference to `exit_group`. A complete
run must observe the full terminal argument 7 and actual exit status 7.

The ELF inspector accepts at most 30 ordinary instructions, one direct E8 CALL,
one C3 RET and those three syscalls. It checks the emitted instruction bytes,
closed control path, register widths and symbolic P/H/T dependencies. The helper
must actually compute P+7, and the continuation must use its returned H to compute
H−T. A coincidentally constant terminal result does not satisfy the contract.
Unsupported compiler emission, natural paging refusal, allocation failure and
timeout remain failed experiments with retained prefixes.

The ordinary instruction set is restricted to the reviewed register
MOV/LEA/ADD/SUB/NOP forms. Explicit RSP writes, other memory operands, spills,
PUSH/POP, indirect control and vector/system instructions refuse. Actual entry
RSP must be 16-byte aligned. CALL changes exactly `[S−8,S)`, the helper runs at
S−8, and RET restores S. All other stack bytes, original code bytes and the
required full state are compared within each lane. Absolute addresses, PIDs and
unrelated initial register/XSTATE values are not compared across launches.

Only pages containing the executed CALL encoding are admitted. A CALL ending at
a page boundary can push a return address that points into the next, never-executed
NX page.
RET may stop at that address before a successor executes. This consumer earns
boundary or crossing evidence only when its actual compiled geometry has it;
the existing separate native boundary controls retain their own observations.

## Separate observation roles

The public example uses `OriginalResidentWord` and `IdentityAndTermination`.
It validates its real provider inputs, full kernel states, journal and cleanup.
Its stack-history scope is explicitly `not_publicly_observed`.

The private example requires the nondefault `dev-owned-stack-consumer-oracle`
feature. Its hidden entry has a closed CLI and exposes no generic native handle,
completion constructor or arbitrary observer callback. The raw lane executes
the original instructions through its own real owner. The admitted lane uses
the production dispatch and census path, recording one potential CALL row before
opening and retaining it after RET and cleanup. Complete stack evidence has two
commits, fourteen waits, twelve private calls, two original steps and eight A–D
captures. Kernel evidence remains separately counted: three attempts, twenty-four
waits, fifteen states and fact counts `[25,25,20]`.

These numbers are success requirements, not values inserted into failed rows.
The formatter projects actual initialized records and leaves unobserved values
null. The parent driver independently checks the row, process result, pinned
artifacts, exact source and all prerequisite receipts.

## Ownership and accounting

Each physical owner is installed before its first fallible operation. Original
failure and panic payloads remain separate from later retention, cleanup,
retirement, output and mask-restoration outcomes. Actual cleanup must drain the
owner and verify the original application and helper pins. Unknown custody is
fail-stop under the outer supervisor.

The admitted lane reserves the complete observer Q under the unchanged 64 MiB
lifetime source-fact limit. It allocates into installed owners, measures their
actual capacities, debits that amount and finishes the same reservation after
startup and before subsequent original-operation dispatch or reservation. Error
or unwind still attempts settlement and finish. No charge is refunded and no
diagnostic buffer grows across effects.

Q includes both lanes' new retained data, bounded file/argument/output owners,
two complete census observations, the CALL observation, kernel-journal copy,
and the additional partial-prefix mirrors. The latter have two stack-mirror
headers plus a CALL-mirror header, 33 MAX XSTATE capacities and one authenticated
source-window capacity. Each embedded header is counted once; concrete helper
functions sum retained capacity and temporary source values with checked
arithmetic. There is no assumed fit or claimed compiler stack-frame size.
The [SHA accounting derivation](runtime-stack-consumer-sha-accounting.md) covers
the pinned hashing dependency path as part of Q.

Independent steps copy the two census observer prefixes and optional CALL
observation before cleanup, compare them afterward, and compare CALL again after
the same Box transfers from TLS into its retired owner. This includes incomplete
source observations, initialized bytes and allocation identities. An incomplete
mirror cannot claim preservation. The production native/profile/word buffers
remain in their original runtime owners with semantic predicates checked again;
they are not described as a second full native byte-copy.

## Reproduction

Use an exact clean source revision, its locked dependency cache, recorded Rust
and native tools, and an unchanged reserved affinity set of at most eight CPUs.
Keep that same environment and affinity across the prerequisites and consumer.
The following placeholders name actual receipt files and their SHA-256 digests:

```sh
python3 evaluation/admission/run.py --expect-revision "$REVISION"
python3 evaluation/admission/runtime_kernel_consumer.py \
  --expect-revision "$REVISION" \
  --correctness-receipt "$CORRECTNESS_RECEIPT" \
  --correctness-sha256 "$CORRECTNESS_SHA256"
python3 evaluation/admission/runtime_stack_feature_controls.py \
  --expect-revision "$REVISION"
python3 evaluation/admission/runtime_stack_consumer.py \
  --expect-revision "$REVISION" \
  --correctness-receipt "$CORRECTNESS_RECEIPT" \
  --correctness-sha256 "$CORRECTNESS_SHA256" \
  --kernel-consumer-receipt "$KERNEL_RECEIPT" \
  --kernel-consumer-sha256 "$KERNEL_SHA256" \
  --feature-receipt "$FEATURE_RECEIPT" \
  --feature-sha256 "$FEATURE_SHA256"
```

The separate feature command authenticates a complete source-bound method
inventory, then requires exactly the named feature-pure tests in one real
launcher libtest capture. Its filter cannot match a default or native method.
The default workspace suite does not supply this feature-control evidence.

The consumer driver has thirteen fixed command roles:

| Roles | Wall limit per command |
| --- | ---: |
| clang and ld.lld versions | 10 s |
| Compile and link | 180 s |
| Public build, feature Clippy, feature build | 180 s |
| Public protocol, oracle protocol, artifact inspection | 10 s |
| Direct reference | 3 s |
| Public consumer, combined raw/admitted oracle | 60 s |

The public binary is pinned before the feature build; the private binary is
pinned separately. All tool/source/object/ELF/binary identities are rechecked.
Three-second absolute operation deadlines include each segment's preparation
and observation work. CALL/RET boundaries do not renew them. Physical cleanup
has the original owner contract under outer containment; the supervisor allows
three further seconds for descendant cleanup and requires zero adoptees.

The fixed capture limit is 8 MiB, the typed row limit is 64 KiB, C/object/ELF
files are bounded to 1 MiB and tool/example files to 256 MiB. A failure keeps its
receipt and leaves later commands `not_run`. There is no automatic retry or
successful truncation.

Tracked JSON receipts under `results/` record the exact revision, hardware,
toolchain, commands, artifact hashes, statuses and times. Raw logs and private
state stay outside tracked results; public records contain no host paths, PIDs,
raw registers, maps or stack bytes. Source contracts and prospective method
counts are separate from executed qualification evidence.

This finite experiment can contribute evidence for page-admission publication
(claim 1), first-instruction admission within its accepted profile (claim 2),
and systematic tactic validation (claim 4). It does not establish coverage of
every selected opcode, general C execution, performance, B3/B4 completion or the
software preemption clock in claim 3.
