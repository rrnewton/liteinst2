# Native controller evidence boundary

`DynamicSession` executes original code without instrumentation. Its fixtures
qualify specific launch, stop, signal and cleanup behavior. They do not qualify
page publication, instrumented signal entry, dynamic membership, or a browser.
The exact-revision `run.py` protocol records these harnesses with the rest of
the admission corpus, hardware, commands and source hashes. An expected
assertion is evidence only after that revision's run passes.

The ordinary untraced signal oracle runs the same immutable ELF and compares
whole handler records and continuation bytes. Records include all 128 siginfo
bytes, handler stack address and kernel signal mask. Separate cases require two
queued realtime payloads, actual LISTEN/SIGCONT, native EINTR and native
SA_RESTART with an alternate stack. These are specific observable comparisons;
they are not claims of exhaustive signal-frame or exception coverage.

The separate control harness requires static, PIE and interpreter exec-stop
authentication, exact kernel exec return, repeated active interruption, stale
and foreign token refusal, timeout cleanup, independent wait domains, a full
raw-ptrace terminal GPR/flags/XSTATE/memory comparison with corruption controls,
and 14 explicit lifecycle/syscall-personality refusal rows. Cleanup does not
count an issued signal as a terminal receipt, and an unconfirmed SIGKILL cannot
authorize resuming original instructions.

## Kernel ownership argument

The source review uses upstream Linux v7.1.3. Matching a numeric upstream
version does not authenticate a vendor kernel's complete source; the recorded
native tests independently exercise the running kernel. The reviewed files
are available under
`https://raw.githubusercontent.com/gregkh/linux/v7.1.3/kernel/`.

| File | SHA-256 | Relevant functions |
| --- | --- | --- |
| signal.c | c8e3ea51d8cbbd5467477cefcd4c524dddae896925163ce44e043c9453b75a8d | do_notify_parent, ptrace_stop, do_jobctl_trap |
| ptrace.c | 6f158c7b443a7a20c36c36abbe68e012fc3dc8017d73771834648541101e85c8 | ptrace_request: PTRACE_INTERRUPT and PTRACE_LISTEN |
| exit.c | e4c0770ac99a41e6ea6cc71310b99b32daba05c67357aea42c5e1813f42cc61d | exit_notify, eligible_child |
| fork.c | 384aabaa48c2f4bb2d619c6d561be98e62cd9527024c3eccd5853dfc1f3a76ae | copy_signal, copy_process |

The bootstrap uses raw clone with CLONE_PIDFD, no shared VM and exit signal
zero. The pidfd is obtained atomically. A fresh signal structure is zeroed and
CLONE_AUTOREAP is absent. Before SEIZE, exit signal zero avoids the
SIGCHLD-specific automatic-reap rule; `__WALL` includes this clone child. After
SEIZE, both automatic-reap branches require the task to be untraced. The
original tracer remains the exclusive waiter through terminal status and an
empty wait domain. External tracing or reaping violates that ownership.

An interrupt can be satisfied by a real syscall or signal stop. The kernel
clears pending STOP at each new ptrace stop, but a request issued after an
already queued stop can require another stop after resume. The controller must
retain the real event, not replace it with a fabricated interruption. For a
seized job-control trap, the kernel emits SIGTRAP only when no group stop is
active; otherwise it reports the stopping signal. A delayed interrupt therefore
does not authorize treating a still-stopped group as continued.

To retrieve the reviewed source for inspection without adding it to the
repository, run this shell script from the repository root and compare the
printed digests with the table:

```sh
set -eu
mkdir -p target/review-linux
for name in signal ptrace exit fork; do
    curl --fail --silent --show-error --location --max-time 30 \
        --output "target/review-linux/$name.c" \
        "https://raw.githubusercontent.com/gregkh/linux/v7.1.3/kernel/$name.c"
done
sha256sum target/review-linux/signal.c target/review-linux/ptrace.c \
    target/review-linux/exit.c target/review-linux/fork.c
```
