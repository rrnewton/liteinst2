# Freestanding C runtime consumer

This is an unqualified recipe for one compiler-produced static x86-64 executable.
No consumer result is attached yet. It does not establish libc, loader,
interpreter, dynamic linking, memory/stack, signal/thread or general application
support.

The [C source](consumers/runtime_identity.c) performs original getpid and gettid,
uses their actual results in C XOR-plus-seven arithmetic, and invokes original
exit_group. It has no headers, CRT, library calls or fabricated ELF bytes.
Compiler output remains unchanged. An unsupported emitted instruction or
exhausted lifetime budget is a failed/refused experiment, with no fallback or
recompilation inside the run.

The [public API example](../../crates/liteinst-launch/examples/runtime_kernel_consumer.rs)
uses owner-captured Partial sources and the explicit IdentityAndTermination
profile. Its provider accepts exactly those three authentic native64 syscall
inputs. Two native returns must preserve the exact full state outside the
specified syscall changes; the third event must be actual terminal status 7.
The public journal must retain the real phases and immutable completed attempts
through physical session cleanup. There is no selected terminal return, fake
successor or dead-mm NX closure.

Run the unchanged six-command qualification first, at the same clean revision,
configuration, toolchain and hardware/affinity count. Keep its receipt and private
captures. Then run the separate experiment with inherited affinity of one to
eight CPUs; the chosen set must stay unchanged. A portable invocation is:

```text
taskset --cpu-list <same-one-to-eight-available-cpus> python3 evaluation/admission/runtime_kernel_consumer.py --expect-revision <40hex> --correctness-receipt evaluation/admission/results/<qualified-run>.json --correctness-sha256 <64hex>
```

The driver authenticates and replays the six original captures. It observes the
actual clang and ld.lld executable hashes and versions, compiles the C source
to an object, directly links a static ELF, and builds the Rust example. Exact
relative argv, source/object/ELF/example hashes and bounded ELF geometry are
recorded. The compiler and linker do not become Cargo build dependencies; no
default test silently passes when the generated artifact is absent.

The linked ELF runs once without admission as a reference, with expected actual
process exit **7**. It then runs once through the public runtime example, whose
own expected exit is **0** after its checks and cleanup. These are separate
role-specific outcomes, not a general allowance for nonzero command failure.
No cross-process equality of randomized initial stacks or full architecture is
claimed. The controlled lane checks complete state at its syscall boundaries.

Every command uses the existing bounded supervisor: private output at most
8 MiB, exact process ownership and a separate three-second cleanup bound.
Compiler/linker/example-build deadlines are 180 seconds; version/protocol
commands use 10 seconds, the reference 3 seconds and the example watchdog
60 seconds. The latter does not replace the unchanged three-second startup and
per-invocation runtime deadlines or its separate three-second terminate budget.
All six default lifetime limits remain, including 64 MiB source/evidence bytes.
Retirement and unused reservations give no refund.

The C object and ELF each have a 1 MiB file cap. Tool and Rust example hashing
uses a separately bounded, streamed 256 MiB cap. Source/configuration/tool and
artifact identities are rechecked around commands. Failed command logs and
bounded partial compiler outputs remain retained. No command is retried or
reclassified; later commands remain not_run after failure.

Public result JSON contains typed comparisons, actual statuses, cleanup,
hardware metadata and hashes. Host paths, PIDs, raw state/maps and free-form
diagnostics remain in private captures. The example records public metrics only
at held boundaries; those are not final six-axis actual-use measurements after
terminal. The public journal survives owner teardown; it does not claim to keep
all private native history after the owner is dropped. The result supports only
the specific artifact named by its hash, and carries no performance claim or
completed B3 claim.
