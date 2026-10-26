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
The parent return must name the authenticated child, and the child's actual
syscall exit must return zero before its first original instruction runs.
Register, extended-state and signal-mask comparisons cover the finite native
fixtures; a registry transition alone is not native evidence.

Address-space identities distinguish fork's separate mm incarnations. The
registry is not yet connected to native mmap, mprotect, mremap or munmap
invalidation. Its generation field does not certify that application mappings
have remained unchanged. Shared-mm clone, executable aliases, JIT mutation,
module loading and instrumented signal entry remain separate work.

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

The finite corpus has separate denominators:

| Corpus | Outer tests | Required observations |
| --- | ---: | --- |
| `tests/dynamic_fork.rs` | 6 | Independent native state, COW and wait status; lifetime-budget retention; unchanged default and unsupported-syscall refusals; per-task and foreign-session tokens, targeted interrupts and parent death; deadline cleanup; two actual failed forks followed by no invented child records |
| Private `owner/lifecycle/tests.rs` | 5 | Both forced observation orders using actual already-held kernel stops; TF refusal before execution; late payload after child retirement; queued sibling retention and actual interrupt-stop accounting |
| `tests/lifecycle_exec_exit.rs` | 7 | Pure constructor phase, syscall sequencing, refusal invariance, unknown signal scope, saved-resume inheritance and lifetime record bounds |

The independent native comparison runs the identical original ELF under a
separate direct ptrace oracle in an exec-isolated subreaper. Seven checkpoints
cover fork entry, both fork returns, parent wait entry, child exit entry,
parent wait return and the final parent fault. Each compares all 27 register
fields, including full flags, exact XSTATE, fixed stack bytes, COW data and
signal mask. Only the four PID-dependent register fields are substituted,
after checking each against that run's authenticated child PID. Branch paths
restore fixed flags in the original ELF after selecting parent or child;
flags at the fork entry and returns remain untouched. Six corruption controls
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
