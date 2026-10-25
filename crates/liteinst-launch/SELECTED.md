# Selected-instruction reference contract

`selected` represents an invocation as exact decoded bytes, an original logical
PC, an operation with its operands, and a complete stopped register snapshot.
The module grants no permission to run code. `gate::SelectedPageGate` supplies
the explicit single-task execution owner; the original A1 CPUID publisher and
fixed-membership concurrent gate retain their existing contracts.

The caller chooses `NativeProvider`, `ScriptedProvider`, or an implementation of
`InstructionProvider`. Native execution means one actual original operation in
the child. Scripted execution means applying one checked typed replacement
result. A provider fault retains the original input and is distinct from sending
a kernel signal. The events and counters preserve these distinctions.

| Operation | Checked successful effect |
| --- | --- |
| CPUID | EAX/ECX inputs and four zero-extended 32-bit outputs |
| RDRAND, RDSEED | 16-bit partial write, 32-bit zero extension or 64-bit replacement; actual destination including RSP; CF success; OF/SF/ZF/AF/PF cleared; failure requires zero |
| RDPID | Zero-extended 32-bit AUX into the decoded destination |
| RDTSC | Counter split into zero-extended EDX:EAX |
| RDTSCP | Counter plus separate zero-extended ECX AUX |
| Native SYSCALL | Authenticated kernel entry, exit, actual full return state and errno result, or explicit signal/termination |
| Scripted SYSCALL | Side-effect-free getpid/gettid profile only: positive pid_t, RAX result, RCX fallthrough and R11 input flags |

Untouched registers, flags and kernel bookkeeping are retained exactly by pure
completion. Successful CPU completion clears RF; a pure fault preserves it.
Scripted syscall completion accepts only its documented ordinary flag profile.
Native syscall bookkeeping is authenticated separately: a real kernel return
can change `orig_rax`, whereas a pure replacement does not claim a kernel entry.
Memory effects and signal delivery are outside the pure completion model.

Every script row matches the entire invocation, including site, bytes, ABI and
all input registers. Mismatched inputs and invalid completion results leave the
row unconsumed. A valid native request or fault decision consumes one row;
subsequent execution can still refuse. `finish()` checks exact exhaustion.

## Live ownership and refusals

The unsafe constructor inherits the complete-head, immutable private code,
no-code-as-data, no-alias and saved-resume certifications of the original
single-task gate. In addition, TF and RF must be clear at every original
selected entry. An inserted INT3 cannot establish the pre-trap RF value, so the
observed-bit check is not a substitute for that certification. Arbitrary signal
returns and IRET paths are unqualified. Pure RF tests and the direct native
syscall RF oracle do not qualify RF-bearing entry through this trap wrapper.

CPU instructions execute at their original address under a single step, with
the complete resulting state checked against the typed architectural effect.
Native SYSCALL uses authenticated `PTRACE_SYSCALL` entry/exit stops; it does not
single-step through SYSCALL or leak debugger TF into R11. Its return bridge
executes an actual owned private INT3 and restores every byte of the captured
exit GPR/XSTATE image. It does not merely relabel a syscall-exit stop as an
injection stop. Source rearming and sync-core must preserve that completed state.
Only the existing single-task syscall allowlist may execute.

INT 0x80 and SYSENTER require exact per-site declarations to represent their
inputs. SYSENTER also requires an explicit input convention identity. These
declarations supply no successful return convention: scripted success and
native execution of aliases refuse. Explicit provider faults remain available.
Undeclared or mismatched aliases refuse before page publication.

Every fallible invocation closes the wrapper before calling the provider.
Only a verified completion reopens it. Provider errors, unwinding, architectural
faults, application signals and termination cannot be resumed through this API.
Actual kernel signals remain pending; dropping the owner kills and reaps the
child. Providers must return promptly; the deadline is checked after dispatch
but cannot preempt a caller's blocking provider implementation.

All-start scanning, complete cross-page closure, expected-byte authentication
and the qualified CALL-return ledger remain required. Embedded selected starts
still refuse. Consequently prefixed random encodings can refuse because their
selected suffix has no backstop, and default-policy RDPID can refuse because
its suffix is RDSEED. RDPID-only positive fixtures explicitly choose that policy;
they do not demonstrate default-policy coverage. Pure support for all widths
and GPRs is not a claim that every encoding passes live admission.

## Independent evidence

The bounded fixture interpreter implements its own decoder and selected-state
effects, without the production decoder/completion model. It compares complete
callback inputs and outputs, full XSTATE, fixed stack/memory and callback order.
Masked CPUID output is followed by deliberate random instructions whose callbacks
remain mandatory. Interpreter/executable first instructions and a cross-page
selected instruction also run through the gate.

The raw native observer executes original CPU instructions with `CONT` and
authenticated markers on separate NOPs. It captures nondeterministic results
and replays those exact typed results through scripted page execution, comparing
every register, flag, extended-state byte and application-memory byte at both
completion and continuation. Separate native-provider runs check each actual
sample's complete architectural transition and application-memory dataflow.
No unrelated random/timestamp samples are compared or masked away.

Raw native syscall comparisons cover completion and original continuation,
including a forced -EFAULT with no cross-run substitution. getpid comparisons
first assert each run's exact known PID, then substitute only that declared
external identity. Corruption controls require GPR/flag/RSP/XSTATE/memory errors
to fail. A host capability fault is explicitly tested as an original-PC fault,
never counted as a successful native instruction qualification.

This is a closed-world single-task reference increment. It does not establish
general alias returns, all prefix/overlap decodes, full-class A1 publication,
multi-task selected providers, application signal delivery, lifecycle/JIT
support, or a cross-vendor/CET release envelope. Those remain separate work.
