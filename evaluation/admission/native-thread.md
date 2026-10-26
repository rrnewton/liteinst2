# Bounded native thread ownership

The additive `DynamicCreationPolicy::ThreadClone` profile permits one native
x86-64 `clone` from a singleton process leader. Its full-width flags must equal
`CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD` (`0x10f00`),
with no exit signal, a child stack with 128 readable/writable bytes below it, and zero
parent-TID, child-TID and TLS arguments. Default options still refuse creation.
This finite profile does not cover ordinary pthread creation, clone3, vfork,
separate thread groups sharing an mm, namespaces or arbitrary clone flags.

The new task receives a distinct, non-reused TaskId and shares its parent's
ProcessId and address-space identity. Terminal and replaced records remain
retained. Two native task records consume one process and one address-space
record; an allowed later leader exec reserves one additional logical task and
address-space record without creating another native task or process. Exec
with a live sibling and nonleader exec remain refused. Reusing a numeric TID
never replenishes the lifetime bound.

## Native phases and original state

The owner authenticates an actual clone syscall entry, parent creation event
and automatic newborn stop before releasing either task. The parent event
and newborn can be observed in either order. Parent return is an actual syscall
EXIT with the authenticated child TID. The child is at its return-ready automatic
stop with AX zero and its declared new SP, after the one-time syscall-exit
tracing decision. This phase is not labelled as a second clone EXIT.

Complete original state comparisons include general registers, flags,
orig_rax, XSTATE, signal mask, initialized stacks and shared memory. The separate
direct-ptrace oracle is independent of the owner. Original instructions provide
first-user checkpoints and demonstrate shared writes, parent alternate-stack
preservation and child alternate-stack reset. Actual identity-valued return
registers must match the separately authenticated native TID in each run; other
state is not normalized to hide differences.

CET and dynamically managed extended state require explicit qualification.
Linux allocates a new shadow stack for a CLONE_VM child when the parent has
shadow stacks enabled. It can also omit dynamic XTILE_DATA and clear PASID
state. CPUID alone does not identify per-task state. The finite native profile
requires one of two read-only certificates. The first is successful
`PTRACE_ARCH_PRCTL` / `ARCH_SHSTK_STATUS` with an exact zero feature bitmap in
tracer-owned memory. The second authenticates that the native Linux ABI has
neither a shadow-stack status implementation nor a shadow-stack regset. It
requires both exact EINVAL results, successful independent general-register and
FS-base control queries, a native 64-bit register view, and a correctly sized
8-byte regset query whose buffer and descriptor remain unchanged. An arbitrary
errno or missing interface alone is insufficient.

The absence certificate requires the current tracer thread's genuine procfs
status to report exactly `Seccomp: 0` before and after the probes. This rejects
filters that could synthesize errno results, including a concurrent TSYNC
installation under the conforming seccomp ABI. Missing, malformed, duplicate
or nonzero status refuses. A trusted procfs and a conforming, unintercepted
kernel ABI are explicit host requirements; these queries do not attest a vendor
kernel build. Source pins establish the argument, not the running build's
configuration.

The configured regset exists even when shadow stacks are disabled. Its read
returns data or ENODEV; the enabled-but-missing-state failure also uses ENODEV.
Thus ENODEV and a successful zero SSP never establish disabled features.
CPUID and absent procfs feature rows remain insufficient. The full
parent/newborn XSTATE comparator remains. A differing native transition fails
closed before original child instructions execute; no component is masked out.
The original fixture still executes its own status syscall. Its exact result
and output bytes must match the independently established certificate: success
and zero features, or EINVAL with the original output sentinel unchanged.
No register or memory field is removed from the differential comparison.

## Task removal and process reaping

An unconsumed tracer wait grants temporary numeric ownership, but the owner
must acquire a stable pidfd before consuming it. Nonleaders require explicit
`PIDFD_THREAD`; a plain process pidfd returns ENOENT for a live nonleader.
The pin is retained across terminal observations and errors.

A nonleader's consumed tracer terminal wait permits the kernel to release that
thread. Retained thread-pidfd HUP is the independent task-removal witness; it
does not require a natural-parent process wait. Process leaders retain the
existing private real-parent drain requirement. A leader that exits before a
live sibling cannot be reported as physically removed. Its eventual terminal
status and HUP remain separate from the kernel pre-exit event.

`TaskExiting` exposes that authenticated event without a client resume token
and leaves worker control available. Its status is the observed event payload,
not a promise about the later terminal status: Linux can use a shared group-exit
code after another task exits or after a fatal signal. The registry retains an
explicit Exiting state, and `TaskTerminal` records only an actual terminal wait.
Neither event alone claims physical process reaping. SIGKILL through
a thread pidfd is group-fatal, so cleanup does not promise selective thread kill.

Final cleanup still requires the authenticated broker drain, empty tracer wait
domain and HUP on every retained application pidfd. Failure, cancellation and
unwinding retain the same ownership; outer-supervisor cleanup is not accepted
as successful session cleanup. The ordinary host subreaper setting and unrelated
child waitability remain unchanged.

## Reproduction and scope

The complete command remains
`python3 evaluation/admission/run.py --expect-revision <40-hex-source>`.
Its tracked result records the exact source revision and source files, hardware,
commands, outer test counts and cleanup evidence. Native thread fixtures form
a separate cohort from selected-instruction telemetry. Captured subprocess
checks do not inflate outer pass counts. Validation duration measures protocol
overhead, not application or instrumentation performance.

The existing parser, command deadlines, old tests, ignores, comparators and
zero-adoptee gates remain required. Failed attempts stay failed in the tracked
results. The corpus declares 33 added outer cases: twelve public native cases, five
private native cases, eight private CET-certificate control/refusal cases, five
pure shared-mm cases and three pure Exiting-phase cases. Four captured single-test raw-oracle/control invocations add no outer
or parser-nested passes. The independent original-state oracle compares six
clone/first-user checkpoints; the shared-state oracle compares eight. Each
snapshot includes all 27 general-register fields, flags/orig_rax, full XSTATE,
signal mask, two initialized 32-byte stack windows, 512 bytes of data and
unchanged fixture code. Fourteen deliberate state corruptions check the
comparator. The private refusal fixtures additionally retain full 16 KiB
writable storage and the 8 KiB code image.

Separate native cases cover both actual stop observation orders, cancellation
and unwind, a syscall-free deadline, stale/foreign tokens, the lifetime clone
bound, exact flag/argument/default refusals, and exec before clone or after
physical worker removal. An original unprivileged setrlimit forces two real
EAGAIN clone returns; each preserves full captured state except AX, retains
one task/mm, then reaches the original UD2. A leader-first oracle separately
checks the original event payload and actual shared group terminal status.
These cases do not infer support for ordinary pthread or nonzero CET state.

This increment supplies bounded lifecycle prerequisites for claims 1 and 2,
and systematic validation under claim 4 after full qualification. It grants no
page-admission or publication lease and does not establish instrumented thread
or signal-entry admission, mapping/JIT/alias invalidation, full B3/B4, real
applications or claim 3's software preemption clock.

## Kernel source argument

The argument uses upstream Linux v7.1.3. Source pins do not authenticate a
vendor build; native observations and the receipt's kernel-release hash remain
separate evidence. `kernel/fork.c` supplies native flag narrowing, thread-group
creation and alternate-stack behavior. `process.c`, `shstk.c` and FPU sources
establish register and extended-state transitions. The x86 ptrace and
arch-prctl implementations identify the per-task CET
observation contract. In the native x86-64 view, the SHSTK regset is installed
exactly when `CONFIG_X86_USER_SHADOW_STACK` is enabled, with one 8-byte element.
Generic GETREGSET can produce EINVAL for an absent regset or a nonmultiple
length; the fixed correct length excludes the latter. The configured getter
has no EINVAL path. Full PRSTATUS equality with GETREGS checks the view, and
GET_FS checks the reversed arch-prctl dispatch. Other wrapper failures remain
errors. The seccomp implementation permits installation and same-mode filter
stacking, but no return to disabled mode in a surviving thread; procfs reports
that thread's current mode. The pre/post zero observations exclude a lasting
TSYNC filter under the stated host contract. ENODEV remains ambiguous and is
never used as a disabled-state proof.
`exit.c` and `pidfs.c` distinguish thread removal, delayed leader exit,
natural-parent reaping and pidfd HUP.

| v7.1.3 source | SHA-256 |
| --- | --- |
| [kernel/fork.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/fork.c) | `384aabaa48c2f4bb2d619c6d561be98e62cd9527024c3eccd5853dfc1f3a76ae` |
| [kernel/exit.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/exit.c) | `e4c0770ac99a41e6ea6cc71310b99b32daba05c67357aea42c5e1813f42cc61d` |
| [fs/pidfs.c](https://github.com/gregkh/linux/blob/v7.1.3/fs/pidfs.c) | `b762e20997be6188b8ed64edd9ef0bea91fd71d1cd081a8227e96be8f59465b9` |
| [include/uapi/linux/pidfd.h](https://github.com/gregkh/linux/blob/v7.1.3/include/uapi/linux/pidfd.h) | `6579ab06813c83cf25b533896f2026430750fb5ee031934b5ffc5aa307af71b6` |
| [include/uapi/linux/sched.h](https://github.com/gregkh/linux/blob/v7.1.3/include/uapi/linux/sched.h) | `9fa784e828fbd2c523333c3c37ada311d494b76f521350bb0f1003990e286494` |
| [include/linux/sched/signal.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/sched/signal.h) | `5f0fee62369f31213a3a5e11bbe1db2631e108fab38f7b1416947c78a5cfcd4b` |
| [arch/x86/kernel/process.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/process.c) | `7374fadbc5c1f2801f62146044e84fd47cbeadda062817f8b749c06ec26e3b83` |
| [arch/x86/kernel/shstk.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/shstk.c) | `3c3be56da7769217d1549f45024809e61b353efb3610109f0355ab45f2db42e0` |
| [arch/x86/kernel/fpu/core.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/fpu/core.c) | `1f1aefc2e59157e3d449138606555fc85994f81557d287d4bc6ec301ea4f1f93` |
| [arch/x86/kernel/fpu/regset.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/fpu/regset.c) | `870bf686c92f608c8d463c7a09ced9f85b5eb3e3e18c62a1b66ac01e2d97e553` |
| [arch/x86/kernel/cpu/proc.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/cpu/proc.c) | `632af015bc00dac562b8ce5f9f4fdf425b737b1e9b34590d1875aa7b5892b0fc` |
| [arch/x86/kernel/ptrace.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/ptrace.c) | `bc52f48380e5ecbe5580af8d64c9464cfa145cb6514f061ae581964fdc2bec32` |
| [arch/x86/kernel/process_64.c](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/process_64.c) | `a873329933dbbf4f53683a29277231017b571003ba9e11ba56c9e62f26d9e6ce` |
| [arch/x86/include/uapi/asm/prctl.h](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/include/uapi/asm/prctl.h) | `fd0cce03f3ed53b8d2598f905352cc150c84ba7b8005603a63a625024c012279` |
| [arch/x86/include/asm/shstk.h](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/include/asm/shstk.h) | `a68ab5ad608652bb2cb4f7508f6052d9de938039dd6c44f8e415b1e23ca672fe` |
| [arch/x86/include/uapi/asm/ptrace-abi.h](https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/include/uapi/asm/ptrace-abi.h) | `04f3cd620a5f7714f0bf2083d0af85b53f1828d4491d852bf7acf3695373d9f3` |
| [kernel/ptrace.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/ptrace.c) | `6f158c7b443a7a20c36c36abbe68e012fc3dc8017d73771834648541101e85c8` |
| [kernel/regset.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/regset.c) | `9e658f96517ef325ed9c269da8190405f18b0e3b6df5ebf204bb02e0ec3bbb1e` |
| [include/linux/regset.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/regset.h) | `5d8d794e00ace1d01865f310fa39d07224818cc505145c14440e7f8315228c2d` |
| [include/uapi/linux/elf.h](https://github.com/gregkh/linux/blob/v7.1.3/include/uapi/linux/elf.h) | `15613d116a6c77c4826036740dd5023c6a7779c776acd3ac7a1a661fe7432b3c` |
| [kernel/seccomp.c](https://github.com/gregkh/linux/blob/v7.1.3/kernel/seccomp.c) | `faadf7f5f2b9fe3e7f08ab76ac73f37a62b36a86b7f5b2c8389d132620850c8c` |
| [include/linux/seccomp.h](https://github.com/gregkh/linux/blob/v7.1.3/include/linux/seccomp.h) | `07000b35cb4737bf3d4e357ce7ff01e34081815fa96df29f2bf95979b7aaa83a` |
| [fs/proc/array.c](https://github.com/gregkh/linux/blob/v7.1.3/fs/proc/array.c) | `18fd1100d317589f22bdfedbdf2ae114b9765c9652ee15254573f50e9657bfb7` |

Retrieve the exact sources into ignored storage without committing them:

```sh
set -eu
for source in kernel/fork.c kernel/exit.c fs/pidfs.c include/uapi/linux/pidfd.h include/uapi/linux/sched.h include/linux/sched/signal.h arch/x86/kernel/process.c arch/x86/kernel/shstk.c arch/x86/kernel/fpu/core.c arch/x86/kernel/fpu/regset.c arch/x86/kernel/cpu/proc.c arch/x86/kernel/ptrace.c arch/x86/kernel/process_64.c arch/x86/include/uapi/asm/prctl.h arch/x86/include/asm/shstk.h arch/x86/include/uapi/asm/ptrace-abi.h kernel/ptrace.c kernel/regset.c include/linux/regset.h include/uapi/linux/elf.h kernel/seccomp.c include/linux/seccomp.h fs/proc/array.c; do
    destination="target/review-linux-thread/$source"
    mkdir -p "$(dirname "$destination")"
    curl --fail --silent --show-error --location --max-time 30 \
        --output "$destination" \
        "https://raw.githubusercontent.com/gregkh/linux/v7.1.3/$source"
    sha256sum "$destination"
done
```
