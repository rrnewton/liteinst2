# Bounded native fork ownership

The opt-in lifecycle path runs original application code. It does not change
executable bytes or permissions, admit pages, or issue a publication lease.
The original `DynamicSession::launch` policy continues to refuse creation and
later exec before kernel execution. Lifecycle options enable only native
x86-64 `fork`, within a lifetime budget of at most two application task records.
The budget includes terminal records, so a successful fork is not refunded
when its child exits. Failed creation does not invent a child record.

This profile excludes clone, clone3, vfork and later exec. It authenticates the
parent's PID namespace and namespace for children against the tracer's before
fork, so a parent-visible return value is not equated with a tracer TID across
an unqualified translation. The fork profile rejects TF-bearing entry. These
are explicit limits of this increment, not general Linux lifecycle coverage.

## Identity and kernel phases

The initial public Exec event remains the actual kernel exec event. The pure
registry is initialized only after the initial exec syscall exit has been
authenticated, through a constructor with that precise phase contract. This
stop is not relabelled as execution of the first application instruction.
Each later stop binds a non-reused task identity, process identity, address
space identity and sequence. A token for one task cannot inspect or release
another task, a terminal incarnation, or a different session.

The fork intent comes from an authenticated syscall-entry stop. The parent
creation event and newborn automatic stop must agree on the child's identity
before either can be released. They may arrive in either observation order.
Native wait and pidfd ownership is established before fallible interpretation;
late payloads cannot reacquire authority for an already retired numeric TID.
The parent's actual syscall-exit return must name the authenticated child.
The child's automatic stop must have the copied full state with RAX zero.
That child stop is after one-time syscall-exit tracing, before return to user
mode; resuming it does not produce another fork syscall-exit event. A distinct
registry return-ready phase records this fact without inventing an exit.
Register, extended-state and signal-mask comparisons cover the finite native
fixtures; a registry transition alone is not native evidence.

Address-space identities distinguish fork's separate mm incarnations. The
registry is not yet connected to native mmap, mprotect, mremap or munmap
invalidation. Its generation field does not certify that application mappings
have remained unchanged. Shared-mm clone, executable aliases, JIT mutation,
module loading and instrumented signal entry remain separate work.

## Newborn return ordering

The initial implementation expected a child fork syscall-exit event after
releasing the automatic newborn stop. Exact-revision runs at
`ebe1de89a82aeb142c70816992b678b3f5c62683` and diagnostic revision
`8b0655b2301c5b98da51e6b7168b7e477c7293be` failed both forced observation-order
cases. The diagnostic run identified the wait after releasing the newborn;
the actual parent exit and its full-register comparison had passed. These
receipts remain failed, with unchanged timeouts and zero adopted descendants.

Linux v7.1.3 clears the child's syscall-trace work in `copy_process`.
`ret_from_fork` invokes `syscall_exit_to_user_mode`, which reads syscall work
and performs one-time exit reporting before the exit-to-user loop. That later
loop handles the newborn job-control trap. `PTRACE_SYSCALL` at the automatic
stop enables future tracing, but does not repeat the earlier exit work. The
controller therefore begins the child's next syscall phase closed. The pure
registry's older before-exit newborn contract remains distinct and available;
callers must authenticate which phase they report.
This upstream source argument does not authenticate a vendor kernel build;
the exact-run hardware/kernel record and native observations remain separate.

The native first-user fixture places an original UD2 immediately after fork.
With the parent held at its real syscall exit, the child's first original
instruction faults at that exact PC. The separate direct-ptrace oracle checks
the same full fault state, including RAX zero, flags, orig_rax, XSTATE, stack,
data and mask. Fault metadata is compared as observed; it is not stripped to
make the pre-user and user-fault phases look identical.
Its four checkpoints cover fork entry, parent exit, child automatic stop and
child first-user fault. Ten corruption controls separately alter return value,
another general register, RF, orig_rax, PC, stack pointer, XSTATE, stack bytes,
data and mask. The direct oracle runs in its own captured single-test process
with an exact completion witness and physical cleanup, without adding another
outer pass.

The source argument uses these pinned files in addition to the ownership
argument in [native control](native-control.md):

| v7.1.3 source | SHA-256 |
| --- | --- |
| [kernel/fork.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/fork.c) | `384aabaa48c2f4bb2d619c6d561be98e62cd9527024c3eccd5853dfc1f3a76ae` |
| [arch/x86/kernel/process.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/process.c) | `7374fadbc5c1f2801f62146044e84fd47cbeadda062817f8b749c06ec26e3b83` |
| [include/linux/entry-common.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/entry-common.h) | `0b46a8eddb3e5eb8eef179cdeb841a8198dd312395a0904909fb5a09b9b282f9` |
| [kernel/entry/common.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/entry/common.c) | `8431325a298c6c48378a13537422fcb6ac7fc44e8db7f3706839b55c9e2388c0` |
| [kernel/signal.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c) | `c8e3ea51d8cbbd5467477cefcd4c524dddae896925163ce44e043c9453b75a8d` |
| [kernel/ptrace.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/ptrace.c) | `6f158c7b443a7a20c36c36abbe68e012fc3dc8017d73771834648541101e85c8` |

Retrieve and check them without adding downloaded source to the repository:

```sh
set -eu
for source in kernel/fork.c arch/x86/kernel/process.c include/linux/entry-common.h kernel/entry/common.c kernel/signal.c kernel/ptrace.c; do
    destination="target/review-linux-fork/$source"
    mkdir -p "$(dirname "$destination")"
    curl --fail --silent --show-error --location --max-time 30 \
        --output "$destination" \
        "https://raw.githubusercontent.com/gregkh/linux/v7.1.3/$source"
    sha256sum "$destination"
done
```

## Terminal observations and cleanup

A lifecycle TaskTerminal event records the original tracer's terminal wait.
It retains the original pidfd and does not claim physical disappearance. This
lets the parent continue to its natural-parent wait, including wait4, while the
controller still owns the child's cleanup obligation. Waiting for physical
reaping inside the child's terminal event would prevent a held parent from
performing that wait.

The default owner's physical-complete terminal contract is unchanged. Final
session cleanup still requires the private real-parent helper's authenticated
drain, empty tracer wait domain, retained application pidfds at HUP, and the
helper's own terminal wait and HUP. Failed proof retains ownership as described
in [native control](native-control.md). A successful kill request or ptrace
terminal status is insufficient.

Signal delivery retains the complete original siginfo and exact disposition.
The lifecycle registry records unknown queue scope when provenance is unknown;
a familiar si_code does not authenticate task-versus-process queue membership.
This does not establish instrumented handler entry or a complete saved-context
census. A targeted interruption must return an event for the requested task;
other observed task events remain held and queued for the caller.

## Evidence requirements

The exact-revision `evaluation/admission/run.py` protocol remains the
qualification gate. Its JSON binds source, commands, hardware, toolchain,
harness counts, native observations and strict zero-leftover-descendant
cleanup. A proposal, compilation, or model transition alone is unqualified.
The independent native oracle must own its natural-parent reaping domain,
including assertion-failure cleanup; the evaluation supervisor cannot supply
missing cleanup and still count the command as passing.

The native corpus contains three captured single-test oracle invocations:
the positive seven-checkpoint COW/wait run, the intentional-unwind cleanup
control, and the separate four-checkpoint first-user fault run. Each requires
its own successful exit, exact 1/0/0 summary and distinct physical-cleanup
witness. None adds a parser nested pass or an extra outer test.

The finite corpus has separate denominators:

| Corpus | Outer tests | Required observations |
| --- | ---: | --- |
| `tests/dynamic_fork.rs` | 7 | Independent native state, first-user fork fault, COW and wait status; lifetime-budget retention; unchanged default and unsupported-syscall refusals; per-task and foreign-session tokens, targeted interrupts and parent death; deadline cleanup; two actual failed forks followed by no invented child records |
| Private `owner/lifecycle/tests.rs` | 5 | Both forced observation orders using actual already-held kernel stops; TF refusal before execution; late payload after child retirement; queued sibling retention and actual interrupt-stop accounting |
| `tests/lifecycle_exec_exit.rs` | 11 | Pure constructor and newborn return-ready phases, syscall sequencing, refusal invariance, unknown signal scope, saved-resume inheritance and lifetime record bounds |

The independent native comparison runs the identical original ELF under a
separate direct ptrace oracle in an exec-isolated subreaper. Seven checkpoints
cover fork entry, the parent fork return, the child automatic return-ready
stop, parent wait entry, child exit entry, parent wait return and the final
parent fault. Each compares all 27 register
fields, including full flags, exact XSTATE, fixed stack bytes, COW data and
signal mask. Only the four PID-dependent register fields are substituted,
after checking each against that run's authenticated child PID. Branch paths
restore fixed flags in the original ELF after selecting parent or child;
flags at fork entry, the parent return and child automatic stop remain untouched. Six corruption controls
cover general registers, flags, stack pointer, extended state, data and mask.
Original executable bytes are rechecked throughout.

The child must have pidfd POLLIN without HUP after the tracer's terminal wait
while its natural parent remains held. Only after the parent's actual wait4
may the fixture require HUP and the exact exit status. The independent oracle
owns the corresponding cleanup itself, including assertion failures. Its
nested one-test subprocess is authenticated by the outer test's exit-status,
summary and cleanup-witness assertions. A second isolated invocation injects
one exact panic with both actual fork tasks held, catches that same panic,
and requires all retained pidfds at HUP plus ECHILD after unwinding. This is
an intentional failure-path cleanup control, separate from the positive
architectural comparison. Neither invocation is an extra outer pass or one
of the separate 50 selected-instruction telemetry records.

Reproduce qualification with `python3 evaluation/admission/run.py
--expect-revision REVISION`, replacing `REVISION` with the exact 40-hex tested
source recorded in the result. The result's source manifest binds these
fixtures and the script, and records actual hardware and every command. The
existing command deadlines, test cohorts, four historical ignores and strict
zero-adopted-descendant rule remain in force. A failed or timed-out run stays
failed even when some individual tests passed.

These tests support bounded
lifecycle prerequisites for admission and systematic validation. They do not
complete B3, B4, browser coverage, or the software-preemption-clock claim.
