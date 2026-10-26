# Bounded native exec ownership

The composed `DynamicSessionOptions` profile enables one successful later
native x86-64 `execve` per session. It can be used with the existing one-process
or lifetime-two-process fork policy. It runs original code and grants no page
admission or publication authority. Default launch and fork-only options retain
their existing later-exec refusal. `execveat`, nonleader exec, shared-mm creation,
other syscall ABIs and TF-bearing entry remain outside this profile.

Physical process records and logical task/address-space incarnations have
separate lifetime bounds. Exec retains the physical PID, ProcessId, pidfd and
private real parent, while retiring the previous TaskId and address-space
identity and allocating replacements. Old tokens cannot inspect or resume the
new task. Retired records do not replenish either budget. One fork plus one
exec therefore needs two process records and three task/address-space records.
These identities do not authenticate native mapping generations or replace
mmap, alias, JIT or publication-lease invalidation.

## Authenticated phases and interruption

An actual exec syscall entry creates the pending transaction. A later
`PTRACE_EVENT_EXEC` must match its owned leader and former-TID payload. At the held
`PTRACE_EVENT_EXEC` stop, image-entry authentication opens the task's
`/proc/<tid>/exe` file object, then checks
the ELF entry against auxv, executable mappings and the actual interpreter
header in memory. It does not reopen a pre-exec pathname as evidence of the
image selected by the kernel. The initial-launch signal-mask restoration is
not repeated: later exec preserves the application's native mask.

`ExecReplaced` identifies both the prior logical task and the new task. It is
an exec event, not a terminal observation or first-user checkpoint. The
registry's explicit `ExecEvent` phase keeps syscall exit pending. The owner
requires the actual native syscall-exit stop and exact full-register transition
from the event, including the real kernel-provided stack pointer. A separate
original-instruction checkpoint establishes first-user behavior. Extended state
is captured at these phases; it is not inferred to remain stable through
kernel return-to-user work.

An interrupt directed at the historical task can race the physical process's
exec. The resulting replacement event is causal evidence for that request;
it carries a new token and task identity. The default interrupt resolves the
current logical task in the original physical process slot. Stops for another
process remain queued, and each actual stop consumes interruption accounting,
including an exec event.

The legacy pure `observe_exec` operation retains its established pending-exit
behavior. Its historical shared `Exec` label does not independently establish
first-user execution. The explicit new phase prevents the native caller from
relying on that ambiguous name.

## Failed exec and physical ownership

A negative syscall result without an exec event does not prove that the old
address space survived. Linux can return an error after its point of no return
and force a fatal SIGSEGV. This profile refuses such outcomes and retains
cleanup ownership; it does not translate every errno into the pure model's
old-mm-preserving `observe_exec_failure`. That model operation requires the
caller to independently establish the surviving address space.

Successful leader exec does not create another physical process, reacquire a
numeric PID, replace its pidfd, or obtain a second broker Ready message. A
fork child that execs remains waitable by its original application parent.
Tracer terminal status must still be distinguished from physical reaping, so
a held parent can continue to wait4. Final cleanup retains all obligations in
[native control](native-control.md) and [native fork](native-fork.md):
authenticated real-parent drain, tracer-domain emptiness and retained pidfd HUP.
An error, refusal or cancellation retains the same cleanup obligations. A
bounded client error can leave the background owner retaining unresolved
physical ownership; it does not establish a complete cleanup receipt.

## Independent validation contract

The native comparison uses a direct-ptrace original execution separately from
the owner. Static and custom-interpreter images begin with an original
instruction that stores AX into a fixed marker. The original continuation then
establishes a fixed RSP and faults at UD2. The marker is checked before release;
it must be untouched at the exec event and exit and contain the native AX value
after the first instruction. The comparison includes all general registers,
flags, orig_rax, XSTATE, initialized stack/data bytes, signal mask and unchanged
code. The fixture does not erase randomized kernel stack addresses from a
cross-run comparator: exact event-to-exit comparisons are within each run, and
the fixed stack is established by original instructions before the cross-run
checkpoint. This is not a comparison of every randomized startup-stack byte.

Separate original-program queries cover mask preservation, caught and ignored
signal dispositions, alternate-stack reset and close-on-exec descriptors.
Additional cases exercise fork-child exec followed by the original parent's
wait4, root exec followed by fork, prior/foreign tokens, default and unsupported
syscall refusals, the one-exec lifetime limit, interruption races and cancellation
at entry/event/exit. Early and deliberately post-point-of-no-return failures
are refusal-and-cleanup evidence, not successful failed-exec continuation.

The static, interpreter and exec-effects state oracles, the EFAULT, ENOENT
and postpoint EINVAL failure oracles, and an explicit output-unwind control
run as seven captured single-test subprocesses. Each requires exactly one
passing summary and one physical-cleanup witness; these do not add outer or
parser-nested passes. Both output streams are continuously drained, retaining
at most 2 MiB per stream; overflow fails while draining continues. The unwind
control writes 256 KiB to a pipe whose measured capacity is smaller, then
raises an exact expected panic while owning a real stopped task. Completion
requires the retained pidfd at HUP and the isolated wait domain at ECHILD.
This checks that diagnostic output cannot prevent unwinding from reaching
cleanup. These cases are a separate cohort from the 50 selected-instruction
telemetry records. The complete reproduction command is the unchanged
`python3 evaluation/admission/run.py --expect-revision <40-hex-source>`.
The tracked receipt identifies the exact source, hardware, commands, all outer
harness counts and cleanup results. Validation durations measure protocol
overhead, not runtime performance. A failed or incomplete command is not
qualifying evidence. The corpus and parser declare the exact expected counts;
no tests, ignores, deadlines, comparators or zero-adoptee gates are relaxed.

## Kernel source argument

The source argument uses upstream Linux v7.1.3. It does not authenticate a
vendor build; runtime observations and the receipt's kernel-release hash remain
separate evidence.

`fs/exec.c` marks the point of no return in `begin_new_exec`, before replacing
the mm. `fs/binfmt_elf.c` installs the new register frame through ELF_PLAT_INIT,
finalize_exec and START_THREAD. On x86-64, the ELF macro leaves AX for exec's
return value, while `start_thread` sets RIP, RSP, segments and flags. Exec emits
`PTRACE_EVENT_EXEC` before returning zero; the native syscall dispatcher then
sets AX and invokes syscall-exit processing. The event, exit and first user
instruction are therefore separate phases. FPU and PKRU reset in `flush_thread`
is another reason to capture actual extended state at each phase.

The error path in `fs/exec.c` can force SIGSEGV after the point of no return and
still return a negative result. `kernel/signal.c` implements this through
SIGSEGV/SI_KERNEL; it is not an unconditional SIGKILL. Exec also resets caught
handlers and the alternate stack, closes CLOEXEC descriptors, and resets the
process exit signal to SIGCHLD. The existing broker's `__WALL` waits cover that
exit-signal change.

| v7.1.3 source | SHA-256 |
| --- | --- |
| [fs/exec.c](https://github.com/gregkh/linux/blob/v7.1.3/fs/exec.c) | `5719b011ce9fdb29ae18247e11633ce5545c138ed21168c73c1cdcebe4fe5889` |
| [include/linux/ptrace.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/ptrace.h) | `1150f9a6c9e4dea3247183c16995f8ef4420cdfdb91bf3e4281cfc52e5f9c04c` |
| [arch/x86/kernel/process_64.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/process_64.c) | `a873329933dbbf4f53683a29277231017b571003ba9e11ba56c9e62f26d9e6ce` |
| [fs/binfmt_elf.c](https://github.com/gregkh/linux/blob/v7.1.3/fs/binfmt_elf.c) | `ec882e2f70b9f3647a16496f425f9951d6b494516350d1fec168c59e080b9702` |
| [arch/x86/include/asm/elf.h](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/include/asm/elf.h) | `e23e91aef223b3fdf6fe0e008a0245c26e959497fdf54b6a13b665ace5dcec97` |
| [arch/x86/entry/syscall_64.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/entry/syscall_64.c) | `ddca5075bdbe4d2ff212edfb6cd5fc7f426a51030a771bbeaca03fb990445b0e` |
| [include/linux/entry-common.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/entry-common.h) | `0b46a8eddb3e5eb8eef179cdeb841a8198dd312395a0904909fb5a09b9b282f9` |
| [kernel/signal.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c) | `c8e3ea51d8cbbd5467477cefcd4c524dddae896925163ce44e043c9453b75a8d` |
| [arch/x86/kernel/process.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/process.c) | `7374fadbc5c1f2801f62146044e84fd47cbeadda062817f8b749c06ec26e3b83` |

Retrieve the exact sources without committing downloaded files:

```sh
set -eu
for source in fs/exec.c include/linux/ptrace.h arch/x86/kernel/process_64.c fs/binfmt_elf.c arch/x86/include/asm/elf.h arch/x86/entry/syscall_64.c include/linux/entry-common.h kernel/signal.c arch/x86/kernel/process.c; do
    destination="target/review-linux-exec/$source"
    mkdir -p "$(dirname "$destination")"
    curl --fail --silent --show-error --location --max-time 30 \
        --output "$destination" \
        "https://raw.githubusercontent.com/gregkh/linux/v7.1.3/$source"
    sha256sum "$destination"
done
```

This increment supplies bounded lifecycle prerequisites for claims 1 and 2,
and systematic validation evidence for claim 4 when its complete protocol
passes. It does not establish instrumented exec admission, arbitrary Linux
lifecycle coverage, mapping/alias/JIT invalidation, real-application release,
persistent-artifact verification or claim 3's software preemption clock.
